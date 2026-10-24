#include "auth/security_key_authenticator.h"

#include "auth/pam_authenticator.h"
#include "auth/pam_helper_protocol.h"
#include "core/deferred_call.h"
#include "core/inotify/inotify.h"
#include "core/log.h"
#include "i18n/i18n.h"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <poll.h>
#include <string_view>
#include <sys/eventfd.h>
#include <unistd.h>
#include <utility>

namespace {
  constexpr Logger kLog("security-key");

  void clearPin(std::string& pin) {
    volatile char* ptr = pin.empty() ? nullptr : pin.data();
    for (std::size_t i = 0; i < pin.size(); ++i) {
      ptr[i] = '\0';
    }
    pin.clear();
  }

  // A new hidraw node gets its uaccess ACL a moment after it appears.
  constexpr auto kHotplugSettleDelay = std::chrono::milliseconds(500);
  [[nodiscard]] int pollRetrying(pollfd* fds, nfds_t count, int timeoutMs) {
    int rc = -1;
    do {
      rc = ::poll(fds, count, timeoutMs);
    } while (rc < 0 && errno == EINTR);
    return rc;
  }

  // True if cancelled before the delay ran out.
  [[nodiscard]] bool waitCancelled(int cancelFd, std::chrono::milliseconds delay) {
    pollfd fd{.fd = cancelFd, .events = POLLIN, .revents = 0};
    return pollRetrying(&fd, 1, static_cast<int>(delay.count())) != 0;
  }

  // Blocks until a hidraw device appears or changes permissions; true if cancelled.
  [[nodiscard]] bool waitForHidraw(int cancelFd, Inotify& devWatch) {
    while (true) {
      pollfd fds[2] = {
          {.fd = cancelFd, .events = POLLIN, .revents = 0},
          {.fd = devWatch.fd(), .events = POLLIN, .revents = 0},
      };
      if (pollRetrying(fds, 2, -1) < 0 || fds[0].revents != 0) {
        return true;
      }
      bool hidraw = false;
      devWatch.drain([&hidraw](const inotify_event* event) {
        if ((event->mask & IN_Q_OVERFLOW) != 0
            || (event->len > 0 && std::string_view(event->name).starts_with("hidraw"))) {
          hidraw = true;
        }
      });
      if (hidraw) {
        if (waitCancelled(cancelFd, kHotplugSettleDelay)) {
          return true;
        }
        devWatch.drain();
        return false;
      }
    }
  }
} // namespace

SecurityKeyAuthenticator::~SecurityKeyAuthenticator() { stop(); }

void SecurityKeyAuthenticator::setAuthenticatedCallback(AuthenticatedCallback callback) {
  m_onAuthenticated = std::move(callback);
}

void SecurityKeyAuthenticator::setCueCallback(CueCallback callback) { m_onCue = std::move(callback); }

void SecurityKeyAuthenticator::setGaveUpCallback(GaveUpCallback callback) { m_onGaveUp = std::move(callback); }

void SecurityKeyAuthenticator::setPinCallback(PinCallback callback) { m_onPin = std::move(callback); }

void SecurityKeyAuthenticator::start(bool watchHotplug) { startWorker(watchHotplug, {}); }

void SecurityKeyAuthenticator::startWithPin(std::string pin) {
  if (pin.empty()) {
    // Never tried on the key: an empty PIN still uses up a retry.
    start(false);
    return;
  }
  startWorker(false, std::move(pin));
}

void SecurityKeyAuthenticator::startWorker(bool watchHotplug, std::string pin) {
  stop();
  m_token = std::make_shared<int>(0);
  if (!PamAuthenticator::securityKeyServiceAvailable()) {
    // Built without -Dpam_service_security_key: give up at once, so the lock
    // screen sequence moves on to the password.
    kLog.debug("built without -Dpam_service_security_key; security key unlock disabled");
    if (!watchHotplug) {
      post(m_token, [](SecurityKeyAuthenticator& self) {
        if (self.m_onGaveUp) {
          self.m_onGaveUp(false);
        }
      });
    }
    return;
  }
  m_cancelFd = ::eventfd(0, EFD_CLOEXEC);
  if (m_cancelFd < 0) {
    kLog.warn("eventfd failed; security key unlock disabled");
    clearPin(pin);
    return;
  }
  // Pre-translated on the main thread: PAM runs on the worker.
  PamAuthenticator::Messages messages{
      .startFailed = i18n::tr("auth.pam.start-failed"),
      .userUnavailable = i18n::tr("auth.pam.user-unavailable"),
      .authenticationFailed = i18n::tr("auth.pam.authentication-failed"),
  };
  m_worker = std::thread([this, cancelFd = m_cancelFd, messages = std::move(messages),
                          token = std::weak_ptr<void>(m_token), watchHotplug, pin = std::move(pin)]() mutable {
    runAttempts(cancelFd, messages, token, watchHotplug, pin);
    clearPin(pin);
  });
}

void SecurityKeyAuthenticator::stop() {
  m_token.reset();
  if (m_worker.joinable()) {
    const std::uint64_t one = 1;
    const ssize_t written = ::write(m_cancelFd, &one, sizeof(one));
    if (written < 0) {
      kLog.warn("failed to signal security key worker eventfd: errno={}", errno);
    }
    m_worker.join();
  }
  if (m_cancelFd >= 0) {
    ::close(m_cancelFd);
    m_cancelFd = -1;
  }
}

void SecurityKeyAuthenticator::post(std::weak_ptr<void> token, std::function<void(SecurityKeyAuthenticator&)> fn) {
  DeferredCall::callLater([this, token = std::move(token), fn = std::move(fn)]() {
    if (!token.expired()) {
      fn(*this);
    }
  });
}

void SecurityKeyAuthenticator::runAttempts(
    int cancelFd, const PamAuthenticator::Messages& messages, const std::weak_ptr<void>& token, bool watchHotplug,
    std::string& pin
) {
  // Watch /dev before the first attempt, so a key plugged in right after a
  // failed one isn't missed.
  Inotify devWatch;
  const bool hotplug = devWatch.watch("/dev", IN_CREATE | IN_ATTRIB).has_value();
  if (watchHotplug && !hotplug) {
    kLog.warn("cannot watch /dev; security key hotplug ignored");
    return;
  }

  const auto gaveUp = [this, &token](bool cued) {
    post(token, [cued](SecurityKeyAuthenticator& self) {
      if (self.m_onGaveUp) {
        self.m_onGaveUp(cued);
      }
    });
  };

  while (true) {
    if (watchHotplug && waitForHidraw(cancelFd, devWatch)) {
      return;
    }
    devWatch.drain();

    PamAuthenticator::Helper helper;
    const bool spawned = PamAuthenticator::spawnHelper(helper, pin, true);
    // The helper has it now (or never will): one attempt per PIN.
    clearPin(pin);
    if (!spawned) {
      kLog.warn("could not start the PAM helper");
      gaveUp(false);
      if (!watchHotplug) {
        return;
      }
      continue;
    }

    bool cued = false;
    bool pinWanted = false;
    bool cancelled = false;
    while (true) {
      pollfd fds[3] = {
          {.fd = cancelFd, .events = POLLIN, .revents = 0},
          {.fd = helper.resultFd, .events = POLLIN, .revents = 0},
          {.fd = helper.infoFd, .events = POLLIN, .revents = 0},
      };
      if (pollRetrying(fds, 3, -1) < 0 || fds[0].revents != 0) {
        cancelled = true;
        break;
      }
      if (fds[2].revents != 0) {
        char buf[16];
        const ssize_t n = ::read(helper.infoFd, buf, sizeof(buf));
        for (ssize_t k = 0; k < n; ++k) {
          if (buf[k] == pam_helper::kInfoPinWanted) {
            pinWanted = true;
          } else if (!cued) {
            cued = true;
            post(token, [](SecurityKeyAuthenticator& self) {
              if (self.m_onCue) {
                self.m_onCue();
              }
            });
          }
        }
        if (n <= 0) {
          // EOF: helper is exiting; keep waiting on the result only.
          ::close(helper.infoFd);
          helper.infoFd = -1;
        }
      }
      if (fds[1].revents != 0) {
        break;
      }
    }

    if (cancelled) {
      PamAuthenticator::cancelHelper(helper);
      return;
    }

    const PamAuthenticator::Result result = PamAuthenticator::finishHelper(helper, messages);
    if (result.success) {
      kLog.info("unlocked with a security key");
      post(token, [](SecurityKeyAuthenticator& self) {
        if (self.m_onAuthenticated) {
          self.m_onAuthenticated();
        }
      });
      return;
    }

    if (pinWanted) {
      // Nothing reached the key: the caller asks for the PIN and tries again.
      kLog.debug("security key wants its PIN");
      post(token, [](SecurityKeyAuthenticator& self) {
        if (self.m_onPin) {
          self.m_onPin();
        } else if (self.m_onGaveUp) {
          self.m_onGaveUp(false);
        }
      });
      if (!watchHotplug) {
        return;
      }
      continue;
    }

    // Touch timed out, a wrong PIN, the key went away (unplugged, suspend), or none enrolled is plugged in.
    kLog.debug("security key attempt failed (cued={}): {}", cued, result.message);
    gaveUp(cued);
    if (!watchHotplug) {
      return;
    }
  }
}
