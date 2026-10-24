#include "auth/security_key_authenticator.h"

#include "auth/pam_authenticator.h"
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

  constexpr std::string_view kPamService = "noctalia-lock-u2f";
  // After a touch timeout (or a failed touch) the key is still there: ask again.
  constexpr auto kRetryDelay = std::chrono::milliseconds(1000);
  // A new hidraw node gets its uaccess ACL a moment after it appears.
  constexpr auto kHotplugSettleDelay = std::chrono::milliseconds(500);
  // The helper could not even start: don't spin.
  constexpr auto kSpawnFailureDelay = std::chrono::milliseconds(5000);

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

void SecurityKeyAuthenticator::setStatusCallback(StatusCallback callback) { m_onStatus = std::move(callback); }

void SecurityKeyAuthenticator::start() {
  if (m_running) {
    return;
  }
  stop();
  m_cancelFd = ::eventfd(0, EFD_CLOEXEC);
  if (m_cancelFd < 0) {
    kLog.warn("eventfd failed; security key unlock disabled");
    return;
  }
  m_token = std::make_shared<int>(0);
  m_running = true;
  std::string language(i18n::Service::instance().language());
  m_worker = std::thread([this, language = std::move(language), token = std::weak_ptr<void>(m_token)]() mutable {
    run(std::move(language), std::move(token));
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

void SecurityKeyAuthenticator::run(std::string language, std::weak_ptr<void> token) {
  runAttempts(m_cancelFd, language, token);
  m_running = false;
}

void SecurityKeyAuthenticator::runAttempts(
    int cancelFd, const std::string& language, const std::weak_ptr<void>& token
) {
  // Watch /dev before the first attempt, so a key plugged in right after a
  // failed one isn't missed.
  Inotify devWatch;
  const bool hotplug = devWatch.watch("/dev", IN_CREATE | IN_ATTRIB).has_value();

  while (true) {
    devWatch.drain();

    PamAuthenticator::Helper helper;
    if (!PamAuthenticator::spawnHelper(helper, "", kPamService, language, true)) {
      kLog.warn("could not start the PAM helper");
      if (waitCancelled(cancelFd, kSpawnFailureDelay)) {
        return;
      }
      continue;
    }

    bool cued = false;
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
        if (n > 0 && !cued) {
          cued = true;
          post(token, [](SecurityKeyAuthenticator& self) {
            if (self.m_onStatus) {
              self.m_onStatus(i18n::tr("lockscreen.security-key-touch"), false);
            }
          });
        } else if (n <= 0) {
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

    PamAuthenticator::Result result;
    const bool finished = PamAuthenticator::finishHelper(helper, result);
    if (finished && result.success) {
      kLog.info("unlocked with a security key");
      post(token, [](SecurityKeyAuthenticator& self) {
        if (self.m_onAuthenticated) {
          self.m_onAuthenticated();
        }
      });
      return;
    }

    if (cued) {
      // Touch timed out, or the key went away (unplugged, suspend).
      kLog.debug("security key attempt failed: {}", result.message);
      post(token, [](SecurityKeyAuthenticator& self) {
        if (self.m_onStatus) {
          self.m_onStatus({}, false);
        }
      });
      if (waitCancelled(cancelFd, kRetryDelay)) {
        return;
      }
      continue;
    }

    // No enrolled key plugged in: wait until one may be.
    if (!hotplug) {
      if (waitCancelled(cancelFd, kSpawnFailureDelay)) {
        return;
      }
      continue;
    }
    if (waitForHidraw(cancelFd, devWatch)) {
      return;
    }
  }
}
