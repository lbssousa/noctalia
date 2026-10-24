#pragma once

#include "auth/pam_authenticator.h"

#include <functional>
#include <memory>
#include <thread>

// Waits for a touch on a FIDO2 security key: runs the PAM helper on the
// security key service (pam_u2f, -Dpam_service_security_key) in the background.
// One attempt, unless started to watch for hotplug: then it waits for a
// hidraw device to show up before each attempt, until stopped.
//
// A key registered with its PIN required (+pin in the authfile, or
// pinverification=1) makes pam_u2f ask for the PIN first: an attempt without
// one ends with the PIN callback instead (nothing reaches the key), and the
// caller starts a single attempt again with the PIN.
class SecurityKeyAuthenticator {
public:
  using AuthenticatedCallback = std::function<void()>;
  // pam_u2f found an enrolled key and waits for a touch.
  using CueCallback = std::function<void()>;
  // The attempt ended without an unlock; `cued` tells whether a touch was asked for
  // (it timed out or the key went away) or no enrolled key was plugged in.
  using GaveUpCallback = std::function<void(bool cued)>;
  // A registered key is plugged in and pam_u2f wants its PIN before the touch.
  using PinCallback = std::function<void()>;

  SecurityKeyAuthenticator() = default;
  ~SecurityKeyAuthenticator();

  SecurityKeyAuthenticator(const SecurityKeyAuthenticator&) = delete;
  SecurityKeyAuthenticator& operator=(const SecurityKeyAuthenticator&) = delete;

  void setAuthenticatedCallback(AuthenticatedCallback callback);
  void setCueCallback(CueCallback callback);
  void setGaveUpCallback(GaveUpCallback callback);
  void setPinCallback(PinCallback callback);

  // Restarts the worker. With `watchHotplug`, every attempt waits for a hidraw device first.
  void start(bool watchHotplug);
  // One attempt that answers pam_u2f's PIN prompt with `pin` (cleared here).
  void startWithPin(std::string pin);
  void stop();

private:
  void startWorker(bool watchHotplug, std::string pin);
  void runAttempts(
      int cancelFd, const PamAuthenticator::Messages& messages, const std::weak_ptr<void>& token, bool watchHotplug,
      std::string& pin
  );
  void post(std::weak_ptr<void> token, std::function<void(SecurityKeyAuthenticator&)> fn);

  AuthenticatedCallback m_onAuthenticated;
  CueCallback m_onCue;
  GaveUpCallback m_onGaveUp;
  PinCallback m_onPin;

  std::thread m_worker;
  // Wakes the worker up to stop it.
  int m_cancelFd = -1;
  // Replaced on every start(); results from an older run are dropped.
  std::shared_ptr<void> m_token;
};
