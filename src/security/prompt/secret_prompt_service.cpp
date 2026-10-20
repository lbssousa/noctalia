#include "security/prompt/secret_prompt_service.h"

#include "core/log.h"
#include "security/prompt/prompt_socket_path.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>

namespace {

  constexpr Logger kLog("secret-prompt");
  // Longest line accepted from a client; real requests stay far below the Assuan limit.
  constexpr std::size_t kMaxPendingInput = 16 * 1024;

  using secret_prompt::AssuanSession;
  using secret_prompt::PromptOrigin;

  std::string_view originName(PromptOrigin origin) { return origin == PromptOrigin::Gpg ? "pinentry" : "askpass"; }

} // namespace

struct SecretPromptService::Listener {
  PromptOrigin origin;
  int fd = -1;
  std::string path;
};

struct SecretPromptService::Connection {
  Connection(std::uint64_t connectionId, int socketFd, PromptOrigin origin)
      : id(connectionId), fd(socketFd), session(origin) {}

  ~Connection() {
    secret_prompt::wipe(input);
    secret_prompt::wipe(output);
  }

  std::uint64_t id;
  int fd;
  AssuanSession session;
  std::string input;
  std::string output;
  // The client shut down its write side (e.g. the relay's stdin hit EOF) but may still read.
  bool peerEof = false;
  bool closing = false;
};

SecretPromptService::SecretPromptService() {
  m_listeners.push_back(std::make_unique<Listener>(Listener{.origin = PromptOrigin::Gpg}));
  m_listeners.push_back(std::make_unique<Listener>(Listener{.origin = PromptOrigin::Ssh}));
}

SecretPromptService::~SecretPromptService() {
  for (auto& connection : m_connections) {
    ::close(connection->fd);
  }
  m_connections.clear();
  for (auto& listener : m_listeners) {
    closeListener(*listener);
  }
}

std::string SecretPromptService::socketPath(PromptOrigin origin) {
  std::string display = secret_prompt::waylandDisplayName();
  if (display.empty()) {
    display = "wayland-0";
  }
  return secret_prompt::promptSocketPath(
      origin == PromptOrigin::Gpg ? secret_prompt::kPinentrySocketKind : secret_prompt::kAskpassSocketKind, display
  );
}

void SecretPromptService::setEnabled(bool pinentry, bool askpass) {
  bool changed = false;
  for (auto& listener : m_listeners) {
    const bool want = listener->origin == PromptOrigin::Gpg ? pinentry : askpass;
    if (want && listener->fd < 0) {
      if (bindListener(*listener)) {
        kLog.info("{} socket listening on {}", originName(listener->origin), listener->path);
      }
    } else if (!want && listener->fd >= 0) {
      closeListener(*listener);
      for (auto& connection : m_connections) {
        if (connection->session.request().origin == listener->origin) {
          connection->session.answerCancel(connection->output);
          connection->closing = true;
          flushConnection(*connection);
          changed = true;
        }
      }
    }
  }
  if (changed) {
    std::erase_if(m_connections, [](const auto& connection) {
      if (connection->closing) {
        ::close(connection->fd);
        return true;
      }
      return false;
    });
    refreshActive();
    notify();
  }
}

bool SecretPromptService::active() const noexcept {
  return std::ranges::any_of(m_listeners, [](const auto& listener) { return listener->fd >= 0; });
}

void SecretPromptService::setStateCallback(StateCallback callback) { m_stateCallback = std::move(callback); }

bool SecretPromptService::bindListener(Listener& listener) {
  listener.path = socketPath(listener.origin);
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    kLog.warn("{} disabled: socket() failed: {}", originName(listener.origin), std::strerror(errno));
    return false;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (listener.path.size() >= sizeof(addr.sun_path)) {
    kLog.warn("{} disabled: socket path too long", originName(listener.origin));
    ::close(fd);
    return false;
  }
  std::memcpy(addr.sun_path, listener.path.c_str(), listener.path.size() + 1);

  ::unlink(listener.path.c_str());
  // Owner-only from the start: no window where another user could connect.
  const mode_t previousMask = ::umask(0077);
  const int bound = ::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
  ::umask(previousMask);
  if (bound < 0 || ::listen(fd, 16) < 0) {
    kLog.warn("{} disabled: bind/listen failed: {}", originName(listener.origin), std::strerror(errno));
    ::close(fd);
    ::unlink(listener.path.c_str());
    return false;
  }
  listener.fd = fd;
  return true;
}

void SecretPromptService::closeListener(Listener& listener) {
  if (listener.fd >= 0) {
    ::close(listener.fd);
    listener.fd = -1;
    ::unlink(listener.path.c_str());
  }
}

void SecretPromptService::addPollFds(std::vector<pollfd>& fds) const {
  m_polledFds.clear();
  for (const auto& listener : m_listeners) {
    if (listener->fd >= 0) {
      fds.push_back({.fd = listener->fd, .events = POLLIN, .revents = 0});
      m_polledFds.push_back(listener->fd);
    }
  }
  for (const auto& connection : m_connections) {
    // After EOF the socket stays readable forever; POLLHUP still reports a vanished peer.
    short events = connection->peerEof ? 0 : POLLIN;
    if (!connection->output.empty()) {
      events |= POLLOUT;
    }
    fds.push_back({.fd = connection->fd, .events = events, .revents = 0});
    m_polledFds.push_back(connection->fd);
  }
}

int SecretPromptService::pollTimeoutMs() const {
  if (!m_activeDeadline.has_value()) {
    return -1;
  }
  const auto remaining =
      std::chrono::duration_cast<std::chrono::milliseconds>(*m_activeDeadline - std::chrono::steady_clock::now());
  return static_cast<int>(std::max<std::chrono::milliseconds::rep>(0, remaining.count()));
}

void SecretPromptService::dispatch(const std::vector<pollfd>& fds, std::size_t startIdx) {
  const std::uint64_t previousActive = m_activeId;
  const std::vector<int> polled = m_polledFds;
  for (std::size_t i = 0; i < polled.size() && startIdx + i < fds.size(); ++i) {
    const short revents = fds[startIdx + i].revents;
    if (revents == 0) {
      continue;
    }
    const int fd = polled[i];
    if (auto it = std::ranges::find_if(m_listeners, [fd](const auto& l) { return l->fd == fd; });
        it != m_listeners.end()) {
      acceptConnections(**it);
      continue;
    }
    auto it = std::ranges::find_if(m_connections, [fd](const auto& c) { return c->fd == fd; });
    if (it == m_connections.end()) {
      continue;
    }
    Connection& connection = **it;
    if ((revents & POLLOUT) != 0) {
      flushConnection(connection);
    }
    if ((revents & (POLLHUP | POLLERR)) != 0) {
      // Client gone (gpg-agent killed the pinentry, ssh killed the askpass): drop its request.
      connection.closing = true;
      secret_prompt::wipe(connection.output);
    } else if ((revents & POLLIN) != 0) {
      readConnection(connection);
    }
  }

  checkDeadlines();

  const bool removed = std::erase_if(
                           m_connections,
                           [](const auto& connection) {
                             if (connection->closing && connection->output.empty()) {
                               ::close(connection->fd);
                               return true;
                             }
                             return false;
                           }
                       )
      > 0;
  refreshActive();
  if (removed || m_activeId != previousActive) {
    notify();
  }
}

void SecretPromptService::acceptConnections(Listener& listener) {
  while (true) {
    const int fd = ::accept4(listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      break;
    }
    ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || cred.uid != ::geteuid()) {
      kLog.warn("{}: rejected connection from uid {}", originName(listener.origin), cred.uid);
      ::close(fd);
      continue;
    }
    auto connection = std::make_unique<Connection>(m_nextConnectionId++, fd, listener.origin);
    connection->output = AssuanSession::greeting();
    flushConnection(*connection);
    m_connections.push_back(std::move(connection));
  }
}

void SecretPromptService::readConnection(Connection& connection) {
  char buf[4096];
  while (true) {
    const auto n = ::recv(connection.fd, buf, sizeof(buf), 0);
    if (n > 0) {
      connection.input.append(buf, static_cast<std::size_t>(n));
      ::explicit_bzero(buf, sizeof(buf));
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n == 0) {
      connection.peerEof = true;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
      connection.closing = true;
      secret_prompt::wipe(connection.output);
      return;
    }
    break;
  }
  if (connection.input.size() > kMaxPendingInput) {
    kLog.warn("{}: line too long, closing", originName(connection.session.request().origin));
    connection.closing = true;
    secret_prompt::wipe(connection.output);
    return;
  }
  processInput(connection);
}

void SecretPromptService::processInput(Connection& connection) {
  std::size_t start = 0;
  while (!connection.closing && !connection.session.waiting()) {
    const auto newline = connection.input.find('\n', start);
    if (newline == std::string::npos) {
      break;
    }
    const std::string_view line(connection.input.data() + start, newline - start);
    const auto action = connection.session.feedLine(line, connection.output);
    start = newline + 1;
    if (action == AssuanSession::Action::Close) {
      connection.closing = true;
    }
  }
  if (start > 0) {
    ::explicit_bzero(connection.input.data(), start);
    connection.input.erase(0, start);
  }
  // Nothing more can arrive: close once the last answer is out.
  if (connection.peerEof && !connection.session.waiting()) {
    connection.closing = true;
  }
  flushConnection(connection);
}

void SecretPromptService::flushConnection(Connection& connection) {
  while (!connection.output.empty()) {
    const auto n = ::send(connection.fd, connection.output.data(), connection.output.size(), MSG_NOSIGNAL);
    if (n > 0) {
      ::explicit_bzero(connection.output.data(), static_cast<std::size_t>(n));
      connection.output.erase(0, static_cast<std::size_t>(n));
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    }
    connection.closing = true;
    secret_prompt::wipe(connection.output);
    return;
  }
}

SecretPromptService::Connection* SecretPromptService::activeConnection() {
  auto it = std::ranges::find_if(m_connections, [this](const auto& c) { return c->id == m_activeId; });
  return it != m_connections.end() ? it->get() : nullptr;
}

const SecretPromptService::Connection* SecretPromptService::activeConnection() const {
  auto it = std::ranges::find_if(m_connections, [this](const auto& c) { return c->id == m_activeId; });
  return it != m_connections.end() ? it->get() : nullptr;
}

void SecretPromptService::refreshActive() {
  if (const Connection* current = activeConnection();
      current != nullptr && !current->closing && current->session.waiting()) {
    return;
  }
  // Oldest waiting connection first: requests are shown in arrival order.
  m_activeId = 0;
  m_activeDeadline.reset();
  for (const auto& connection : m_connections) {
    if (!connection->closing && connection->session.waiting()) {
      m_activeId = connection->id;
      if (const int timeout = connection->session.request().timeoutSeconds; timeout > 0) {
        m_activeDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
      }
      break;
    }
  }
}

void SecretPromptService::checkDeadlines() {
  if (!m_activeDeadline.has_value() || std::chrono::steady_clock::now() < *m_activeDeadline) {
    return;
  }
  m_activeDeadline.reset();
  if (Connection* connection = activeConnection(); connection != nullptr) {
    connection->session.answerTimeout(connection->output);
    processInput(*connection);
  }
}

void SecretPromptService::notify() {
  if (m_stateCallback) {
    m_stateCallback();
  }
}

bool SecretPromptService::hasPendingRequest() const noexcept { return activeConnection() != nullptr; }

secret_prompt::PromptRequest SecretPromptService::pendingRequest() const {
  const Connection* connection = activeConnection();
  return connection != nullptr ? connection->session.request() : secret_prompt::PromptRequest{};
}

std::uint64_t SecretPromptService::pendingId() const noexcept { return m_activeId; }

void SecretPromptService::submitSecret(std::string& secret) {
  Connection* connection = activeConnection();
  if (connection == nullptr) {
    secret_prompt::wipe(secret);
    return;
  }
  connection->session.answerPin(secret, connection->output);
  processInput(*connection);
  refreshActive();
  notify();
}

void SecretPromptService::confirm(bool confirmed) {
  if (Connection* connection = activeConnection(); connection != nullptr) {
    connection->session.answerConfirm(confirmed, connection->output);
    processInput(*connection);
    refreshActive();
    notify();
  }
}

void SecretPromptService::cancel() {
  if (Connection* connection = activeConnection(); connection != nullptr) {
    connection->session.answerCancel(connection->output);
    processInput(*connection);
    refreshActive();
    notify();
  }
}

void SecretPromptService::cancelAll() {
  bool any = false;
  for (auto& connection : m_connections) {
    if (connection->session.waiting()) {
      connection->session.answerCancel(connection->output);
      processInput(*connection);
      any = true;
    }
  }
  if (any) {
    refreshActive();
    notify();
  }
}
