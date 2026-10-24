#include "security/prompt/secret_prompt_service.h"
#include "tests/test_check.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace {

  using secret_prompt::PromptKind;
  using secret_prompt::PromptOrigin;

  void pump(SecretPromptService& service, int rounds = 5) {
    for (int i = 0; i < rounds; ++i) {
      std::vector<pollfd> fds;
      service.addPollFds(fds);
      const int timeout = service.pollTimeoutMs();
      ::poll(fds.data(), fds.size(), timeout >= 0 ? std::min(timeout, 20) : 20);
      service.dispatch(fds, 0);
    }
  }

  int connectTo(PromptOrigin origin) {
    const std::string path = SecretPromptService::socketPath(origin);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    TEST_CHECK(fd >= 0);
    TEST_CHECK(::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    return fd;
  }

  void sendText(int fd, std::string_view text) {
    TEST_CHECK(::send(fd, text.data(), text.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(text.size()));
  }

  // Reads whatever the service has sent so far.
  std::string drain(int fd) {
    std::string out;
    char buf[1024];
    while (true) {
      pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
      if (::poll(&p, 1, 20) <= 0) {
        break;
      }
      const auto n = ::recv(fd, buf, sizeof(buf), 0);
      if (n <= 0) {
        break;
      }
      out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
  }

  void testPinWithHalfClose(SecretPromptService& service) {
    const int fd = connectTo(PromptOrigin::Gpg);
    pump(service);
    TEST_CHECK(drain(fd) == "OK Pleased to meet you\n");
    // Like `echo ... | noctalia-pinentry`: everything at once, then EOF on the write side.
    sendText(fd, "SETDESC Unlock%0Akey\nGETPIN\nBYE\n");
    ::shutdown(fd, SHUT_WR);
    pump(service);
    TEST_CHECK(service.hasPendingRequest());
    const auto request = service.pendingRequest();
    TEST_CHECK(request.kind == PromptKind::Pin);
    TEST_CHECK(request.origin == PromptOrigin::Gpg);
    TEST_CHECK(request.description == "Unlock\nkey");
    std::string secret = "hunter2";
    service.submitSecret(secret);
    TEST_CHECK(secret.empty());
    pump(service);
    TEST_CHECK(drain(fd) == "OK\nD hunter2\nOK\nOK closing connection\n");
    TEST_CHECK(!service.hasPendingRequest());
    ::close(fd);
  }

  void testClientVanishes(SecretPromptService& service) {
    const int fd = connectTo(PromptOrigin::Gpg);
    sendText(fd, "GETPIN\n");
    pump(service);
    TEST_CHECK(service.hasPendingRequest());
    ::close(fd);
    pump(service);
    TEST_CHECK(!service.hasPendingRequest());
  }

  void testQueueAndCancel(SecretPromptService& service) {
    const int first = connectTo(PromptOrigin::Gpg);
    sendText(first, "SETDESC first\nGETPIN\n");
    pump(service);
    const int second = connectTo(PromptOrigin::Ssh);
    sendText(second, "OPTION noctalia-visible-input\nSETDESC second\nGETPIN\n");
    pump(service);
    TEST_CHECK(service.pendingRequest().description == "first");
    const auto firstId = service.pendingId();
    service.cancel();
    pump(service);
    TEST_CHECK(drain(first).ends_with("ERR 83886179 Operation cancelled <Pinentry>\n"));
    TEST_CHECK(service.hasPendingRequest());
    TEST_CHECK(service.pendingId() != firstId);
    const auto request = service.pendingRequest();
    TEST_CHECK(request.description == "second");
    TEST_CHECK(request.origin == PromptOrigin::Ssh);
    TEST_CHECK(request.visibleInput);
    service.cancelAll();
    pump(service);
    TEST_CHECK(!service.hasPendingRequest());
    TEST_CHECK(drain(second).ends_with("ERR 83886179 Operation cancelled <Pinentry>\n"));
    ::close(first);
    ::close(second);
    pump(service);
  }

  void testConfirmAndTimeout(SecretPromptService& service) {
    const int fd = connectTo(PromptOrigin::Gpg);
    sendText(fd, "CONFIRM\n");
    pump(service);
    TEST_CHECK(service.pendingRequest().kind == PromptKind::Confirm);
    service.confirm(false);
    pump(service);
    TEST_CHECK(drain(fd).ends_with("ERR 83886194 Not confirmed <Pinentry>\n"));

    sendText(fd, "SETTIMEOUT 1\nGETPIN\n");
    pump(service);
    TEST_CHECK(service.hasPendingRequest());
    TEST_CHECK(service.pollTimeoutMs() >= 0);
    const auto start = std::chrono::steady_clock::now();
    while (service.hasPendingRequest() && std::chrono::steady_clock::now() - start < std::chrono::seconds(3)) {
      pump(service, 1);
    }
    TEST_CHECK(!service.hasPendingRequest());
    TEST_CHECK(drain(fd).ends_with("ERR 83886142 Timeout <Pinentry>\n"));
    ::close(fd);
    pump(service);
  }

} // namespace

int main() {
  char pattern[] = "/tmp/noctalia-secret-prompt-XXXXXX";
  TEST_CHECK(::mkdtemp(pattern) != nullptr);
  ::setenv("XDG_RUNTIME_DIR", pattern, 1);
  ::setenv("WAYLAND_DISPLAY", "wayland-test", 1);

  {
    SecretPromptService service;
    int notifications = 0;
    service.setStateCallback([&notifications]() { ++notifications; });
    service.setEnabled(true, true);
    TEST_CHECK(service.active());
    TEST_CHECK(std::filesystem::exists(SecretPromptService::socketPath(PromptOrigin::Gpg)));
    const auto perms = std::filesystem::status(SecretPromptService::socketPath(PromptOrigin::Ssh)).permissions();
    TEST_CHECK(
        (perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all))
        == std::filesystem::perms::none
    );

    testPinWithHalfClose(service);
    testClientVanishes(service);
    testQueueAndCancel(service);
    testConfirmAndTimeout(service);
    TEST_CHECK(notifications > 0);

    service.setEnabled(false, true);
    TEST_CHECK(!std::filesystem::exists(SecretPromptService::socketPath(PromptOrigin::Gpg)));
    TEST_CHECK(std::filesystem::exists(SecretPromptService::socketPath(PromptOrigin::Ssh)));
  }
  TEST_CHECK(!std::filesystem::exists(SecretPromptService::socketPath(PromptOrigin::Ssh)));
  std::filesystem::remove_all(pattern);
  return 0;
}
