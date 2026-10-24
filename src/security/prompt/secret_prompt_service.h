#pragma once

#include "security/prompt/assuan_session.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <poll.h>
#include <string>
#include <vector>

// Serves graphical pinentry (gpg-agent) and ssh-askpass requests. noctalia-pinentry and
// noctalia-askpass connect to one Unix socket each, speak the pinentry Assuan protocol, and the
// shell answers once the user acts on the "secret-prompt" panel. One request is shown at a time;
// later connections wait their turn.
class SecretPromptService {
public:
  using StateCallback = std::function<void()>;

  SecretPromptService();
  ~SecretPromptService();

  SecretPromptService(const SecretPromptService&) = delete;
  SecretPromptService& operator=(const SecretPromptService&) = delete;

  // Binds or removes each socket. Disabling an origin drops its pending requests (cancelled).
  void setEnabled(bool pinentry, bool askpass);
  [[nodiscard]] bool active() const noexcept;

  void setStateCallback(StateCallback callback);

  void addPollFds(std::vector<pollfd>& fds) const;
  [[nodiscard]] int pollTimeoutMs() const;
  void dispatch(const std::vector<pollfd>& fds, std::size_t startIdx);

  [[nodiscard]] bool hasPendingRequest() const noexcept;
  [[nodiscard]] secret_prompt::PromptRequest pendingRequest() const;
  // Changes whenever a different request becomes the visible one.
  [[nodiscard]] std::uint64_t pendingId() const noexcept;

  // Answers the visible request. `secret` is wiped.
  void submitSecret(std::string& secret);
  void confirm(bool confirmed);
  void cancel();
  // Cancels everything (e.g. the session got locked).
  void cancelAll();

  [[nodiscard]] static std::string socketPath(secret_prompt::PromptOrigin origin);

private:
  struct Listener;
  struct Connection;

  bool bindListener(Listener& listener);
  void closeListener(Listener& listener);
  void acceptConnections(Listener& listener);
  void readConnection(Connection& connection);
  void processInput(Connection& connection);
  void flushConnection(Connection& connection);
  [[nodiscard]] Connection* activeConnection();
  [[nodiscard]] const Connection* activeConnection() const;
  void refreshActive();
  void checkDeadlines();
  void notify();

  std::vector<std::unique_ptr<Listener>> m_listeners;
  std::vector<std::unique_ptr<Connection>> m_connections;
  // fd order handed to the main loop, so dispatch() can map revents back.
  mutable std::vector<int> m_polledFds;
  std::uint64_t m_nextConnectionId = 1;
  std::uint64_t m_activeId = 0;
  std::optional<std::chrono::steady_clock::time_point> m_activeDeadline;
  StateCallback m_stateCallback;
};
