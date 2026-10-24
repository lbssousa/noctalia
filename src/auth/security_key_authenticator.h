#pragma once

#include <functional>
#include <memory>
#include <thread>

// Waits for a touch on a FIDO2 security key: runs the PAM helper on the
// "noctalia-lock-u2f" service (pam_u2f) in the background. One attempt, unless
// started to watch for hotplug: then it waits for a hidraw device to show up
// before each attempt, until stopped.
class SecurityKeyAuthenticator {
public:
  using AuthenticatedCallback = std::function<void()>;
  // pam_u2f found an enrolled key and waits for a touch.
  using CueCallback = std::function<void()>;
  // The attempt ended without an unlock; `cued` tells whether a touch was asked for
  // (it timed out or the key went away) or no enrolled key was plugged in.
  using GaveUpCallback = std::function<void(bool cued)>;

  SecurityKeyAuthenticator() = default;
  ~SecurityKeyAuthenticator();

  SecurityKeyAuthenticator(const SecurityKeyAuthenticator&) = delete;
  SecurityKeyAuthenticator& operator=(const SecurityKeyAuthenticator&) = delete;

  void setAuthenticatedCallback(AuthenticatedCallback callback);
  void setCueCallback(CueCallback callback);
  void setGaveUpCallback(GaveUpCallback callback);

  // Restarts the worker. With `watchHotplug`, every attempt waits for a hidraw device first.
  void start(bool watchHotplug);
  void stop();

private:
  void runAttempts(int cancelFd, const std::string& language, const std::weak_ptr<void>& token, bool watchHotplug);
  void post(std::weak_ptr<void> token, std::function<void(SecurityKeyAuthenticator&)> fn);

  AuthenticatedCallback m_onAuthenticated;
  CueCallback m_onCue;
  GaveUpCallback m_onGaveUp;

  std::thread m_worker;
  // Wakes the worker up to stop it.
  int m_cancelFd = -1;
  // Replaced on every start(); results from an older run are dropped.
  std::shared_ptr<void> m_token;
};
