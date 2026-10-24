#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

// Waits for a touch on a FIDO2 security key: runs the PAM helper on the
// "noctalia-lock-u2f" service (pam_u2f) in the background, alongside the
// password field and the fingerprint reader, and again whenever a hidraw
// device shows up.
class SecurityKeyAuthenticator {
public:
  using AuthenticatedCallback = std::function<void()>;
  using StatusCallback = std::function<void(const std::string& message, bool isError)>;

  SecurityKeyAuthenticator() = default;
  ~SecurityKeyAuthenticator();

  SecurityKeyAuthenticator(const SecurityKeyAuthenticator&) = delete;
  SecurityKeyAuthenticator& operator=(const SecurityKeyAuthenticator&) = delete;

  void setAuthenticatedCallback(AuthenticatedCallback callback);
  void setStatusCallback(StatusCallback callback);

  void start();
  void stop();

private:
  void run(std::string language, std::weak_ptr<void> token);
  void runAttempts(int cancelFd, const std::string& language, const std::weak_ptr<void>& token);
  void post(std::weak_ptr<void> token, std::function<void(SecurityKeyAuthenticator&)> fn);

  AuthenticatedCallback m_onAuthenticated;
  StatusCallback m_onStatus;

  std::thread m_worker;
  // False once the worker has returned on its own (after a successful touch).
  std::atomic<bool> m_running = false;
  // Wakes the worker up to stop it.
  int m_cancelFd = -1;
  // Replaced on every start(); results from an older run are dropped.
  std::shared_ptr<void> m_token;
};
