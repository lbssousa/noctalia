#include "security/fingerprint_manager.h"

#include "core/deferred_call.h"
#include "core/log.h"
#include "dbus/system_bus.h"
#include "i18n/i18n.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <string>
#include <utility>

namespace {
  constexpr Logger kLog("fingerprint-manager");

  const sdbus::ServiceName kFprintBusName{"net.reactivated.Fprint"};
  const sdbus::ObjectPath kManagerPath{"/net/reactivated/Fprint/Manager"};
  constexpr auto kManagerInterface = "net.reactivated.Fprint.Manager";
  constexpr auto kDeviceInterface = "net.reactivated.Fprint.Device";

  const sdbus::ServiceName kDbusBusName{"org.freedesktop.DBus"};
  const sdbus::ObjectPath kDbusPath{"/org/freedesktop/DBus"};
  constexpr auto kDbusInterface = "org.freedesktop.DBus";

  // Claim and EnrollStart may wait on a polkit prompt; the default 25 s D-Bus timeout is too short.
  constexpr auto kInteractiveTimeout = std::chrono::minutes(2);
  constexpr auto kVerifyTimeout = std::chrono::seconds(30);

  std::string errorMessage(const sdbus::Error& error) {
    static const std::map<std::string, std::string> kErrors = {
        {"net.reactivated.Fprint.Error.PermissionDenied", "settings.fingerprint.error.permission-denied"},
        {"net.reactivated.Fprint.Error.AlreadyInUse", "settings.fingerprint.error.in-use"},
        {"net.reactivated.Fprint.Error.NoEnrolledPrints", "settings.fingerprint.error.no-prints"},
        {"net.reactivated.Fprint.Error.PrintsNotDeleted", "settings.fingerprint.error.not-deleted"},
        {"net.reactivated.Fprint.Error.NoSuchDevice", "settings.fingerprint.error.no-device"},
    };
    const auto it = kErrors.find(std::string(error.getName()));
    if (it != kErrors.end()) {
      return i18n::tr(it->second);
    }
    return i18n::tr("settings.fingerprint.error.generic", "message", error.getMessage());
  }

  // fprintd scan feedback shared by enroll and verify ("enroll-retry-scan", "verify-retry-scan").
  std::optional<std::string> retryMessage(std::string_view suffix) {
    if (suffix == "retry-scan") {
      return i18n::tr("settings.fingerprint.status.retry-scan");
    }
    if (suffix == "swipe-too-short") {
      return i18n::tr("settings.fingerprint.status.swipe-too-short");
    }
    if (suffix == "finger-not-centered") {
      return i18n::tr("settings.fingerprint.status.finger-not-centered");
    }
    if (suffix == "remove-and-retry") {
      return i18n::tr("settings.fingerprint.status.remove-and-retry");
    }
    return std::nullopt;
  }

  std::string touchPrompt(const std::vector<FingerprintDevice>& devices, const std::string& path) {
    const auto it = std::ranges::find(devices, path, &FingerprintDevice::path);
    if (it != devices.end() && it->scanType == "swipe") {
      return i18n::tr("settings.fingerprint.status.swipe");
    }
    return i18n::tr("settings.fingerprint.status.touch");
  }
} // namespace

FingerprintManager::FingerprintManager(SystemBus& bus) : m_bus(bus) {}

FingerprintManager::~FingerprintManager() {
  m_alive.reset();
  m_verifyTimeout.stop();
  if (m_device != nullptr && m_claimed) {
    try {
      m_device->callMethod("Release").onInterface(kDeviceInterface);
    } catch (const sdbus::Error&) {
    }
  }
}

void FingerprintManager::setChangedCallback(ChangedCallback callback) { m_onChanged = std::move(callback); }

bool FingerprintManager::serviceAvailable() {
  if (m_serviceAvailable.has_value()) {
    return *m_serviceAvailable;
  }
  bool available = m_bus.nameHasOwner(std::string(kFprintBusName));
  if (!available) {
    try {
      auto dbus = sdbus::createProxy(m_bus.connection(), kDbusBusName, kDbusPath);
      std::vector<std::string> names;
      dbus->callMethod("ListActivatableNames").onInterface(kDbusInterface).storeResultsTo(names);
      available = std::ranges::contains(names, std::string(kFprintBusName));
    } catch (const sdbus::Error& e) {
      kLog.debug("could not list activatable names: {}", e.what());
    }
  }
  m_serviceAvailable = available;
  return available;
}

void FingerprintManager::refresh() {
  if (m_loading || busy()) {
    return;
  }
  m_loading = true;
  try {
    if (m_manager == nullptr) {
      m_manager = sdbus::createProxy(m_bus.connection(), kFprintBusName, kManagerPath);
    }
  } catch (const sdbus::Error& e) {
    kLog.warn("could not create fprintd manager proxy: {}", e.what());
    m_loading = false;
    m_loaded = true;
    notifyChanged();
    return;
  }

  // GetDevices D-Bus-activates fprintd on first use, which can take a moment: keep it async.
  m_manager->callMethodAsync("GetDevices")
      .onInterface(kManagerInterface)
      .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive)](
                           std::optional<sdbus::Error> e, std::vector<sdbus::ObjectPath> paths
                       ) {
        if (alive.expired()) {
          return;
        }
        m_loading = false;
        m_loaded = true;
        if (e.has_value()) {
          kLog.info("could not list fingerprint readers: {}", e->what());
          paths.clear();
        }

        std::vector<FingerprintDevice> devices;
        for (const auto& path : paths) {
          FingerprintDevice device{.path = path, .name = path, .scanType = "press"};
          try {
            auto proxy = sdbus::createProxy(m_bus.connection(), kFprintBusName, path);
            device.name = proxy->getProperty("name").onInterface(kDeviceInterface).get<std::string>();
            device.scanType = proxy->getProperty("scan-type").onInterface(kDeviceInterface).get<std::string>();
          } catch (const sdbus::Error& err) {
            kLog.debug("could not read fingerprint reader properties: {}", err.what());
          }
          devices.push_back(std::move(device));
        }
        m_devices = std::move(devices);

        if (std::ranges::find(m_devices, m_selectedPath, &FingerprintDevice::path) == m_devices.end()) {
          m_selectedPath = m_devices.empty() ? std::string{} : m_devices.front().path;
          dropDeviceProxyLater();
        }
        if (m_selectedPath.empty()) {
          m_enrolled.clear();
          notifyChanged();
          return;
        }
        // The proxy may be dropped on the next loop iteration; list on a fresh one afterwards.
        DeferredCall::callLater([this, alive]() {
          if (!alive.expired()) {
            loadEnrolled();
          }
        });
      });
}

void FingerprintManager::selectDevice(const std::string& path) {
  if (path == m_selectedPath || busy()) {
    return;
  }
  m_selectedPath = path;
  m_enrolled.clear();
  clearStatus();
  dropDeviceProxyLater();
  DeferredCall::callLater([this, alive = std::weak_ptr<void>(m_alive)]() {
    if (!alive.expired()) {
      loadEnrolled();
    }
  });
  notifyChanged();
}

bool FingerprintManager::ensureDeviceProxy() {
  if (m_device != nullptr) {
    return true;
  }
  if (m_selectedPath.empty()) {
    return false;
  }
  try {
    m_device = sdbus::createProxy(m_bus.connection(), kFprintBusName, sdbus::ObjectPath{m_selectedPath});
  } catch (const sdbus::Error& e) {
    kLog.warn("could not create fingerprint reader proxy: {}", e.what());
    return false;
  }
  m_device->uponSignal("EnrollStatus").onInterface(kDeviceInterface).call([this](const std::string& result, bool done) {
    handleEnrollStatus(result, done);
  });
  m_device->uponSignal("VerifyStatus").onInterface(kDeviceInterface).call([this](const std::string& result, bool done) {
    handleVerifyStatus(result, done);
  });
  m_device->uponSignal("VerifyFingerSelected").onInterface(kDeviceInterface).call([this](const std::string& finger) {
    if (m_mode == Mode::Verifying) {
      m_matchedFinger = finger;
    }
  });
  return true;
}

void FingerprintManager::dropDeviceProxyLater() {
  if (m_device == nullptr) {
    return;
  }
  // Never destroy a proxy from inside one of its own reply handlers.
  DeferredCall::callLater([this, alive = std::weak_ptr<void>(m_alive)]() {
    if (alive.expired() || busy()) {
      return;
    }
    m_device.reset();
    m_claimed = false;
  });
}

void FingerprintManager::loadEnrolled() {
  if (!ensureDeviceProxy()) {
    m_enrolled.clear();
    notifyChanged();
    return;
  }
  // Empty user name: fprintd uses the caller's user.
  m_device->callMethodAsync("ListEnrolledFingers")
      .onInterface(kDeviceInterface)
      .withArguments(std::string{})
      .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive)](
                           std::optional<sdbus::Error> e, std::vector<std::string> fingers
                       ) {
        if (alive.expired()) {
          return;
        }
        if (e.has_value()) {
          // NoEnrolledPrints is the normal "nothing enrolled yet" answer.
          if (e->getName() != sdbus::Error::Name{"net.reactivated.Fprint.Error.NoEnrolledPrints"}) {
            kLog.info("could not list enrolled fingers: {}", e->what());
          }
          fingers.clear();
        }
        m_enrolled = std::move(fingers);
        notifyChanged();
      });
}

void FingerprintManager::claimThen(std::function<void()> next) {
  if (!ensureDeviceProxy()) {
    setStatus(i18n::tr("settings.fingerprint.error.no-device"), true);
    finishOperation();
    return;
  }
  if (m_claimed) {
    next();
    return;
  }
  m_claiming = true;
  m_device->callMethodAsync("Claim")
      .onInterface(kDeviceInterface)
      .withTimeout(kInteractiveTimeout)
      .withArguments(std::string{})
      .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive),
                        next = std::move(next)](std::optional<sdbus::Error> e) {
        if (alive.expired()) {
          return;
        }
        m_claiming = false;
        if (e.has_value()) {
          kLog.info("could not claim fingerprint reader: {}", e->what());
          setStatus(errorMessage(*e), true);
          finishOperation();
          return;
        }
        m_claimed = true;
        if (m_mode == Mode::Idle) {
          // Cancelled while the claim was pending.
          release();
          return;
        }
        next();
      });
}

void FingerprintManager::release() {
  if (m_device == nullptr || !m_claimed) {
    return;
  }
  m_claimed = false;
  m_device->callMethodAsync("Release").onInterface(kDeviceInterface).uponReplyInvoke([](std::optional<sdbus::Error> e) {
    if (e.has_value()) {
      kLog.debug("could not release fingerprint reader: {}", e->what());
    }
  });
}

void FingerprintManager::finishOperation() {
  m_verifyTimeout.stop();
  m_mode = Mode::Idle;
  release();
  notifyChanged();
}

void FingerprintManager::deleteFinger(const std::string& finger) {
  if (busy()) {
    return;
  }
  clearStatus();
  // Claim is required by DeleteEnrolledFinger; borrow the Verifying mode so cancel() and the
  // claim callback treat it as a running operation.
  m_mode = Mode::Verifying;
  claimThen([this, finger]() {
    m_device->callMethodAsync("DeleteEnrolledFinger")
        .onInterface(kDeviceInterface)
        .withTimeout(kInteractiveTimeout)
        .withArguments(finger)
        .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive), finger](std::optional<sdbus::Error> e) {
          if (alive.expired()) {
            return;
          }
          if (e.has_value()) {
            kLog.info("could not delete fingerprint: {}", e->what());
            setStatus(errorMessage(*e), true);
          } else {
            std::erase(m_enrolled, finger);
            setStatus(i18n::tr("settings.fingerprint.status.deleted", "finger", fingerLabel(finger)), false);
          }
          finishOperation();
          DeferredCall::callLater([this, alive]() {
            if (!alive.expired() && !busy()) {
              loadEnrolled();
            }
          });
        });
  });
  notifyChanged();
}

void FingerprintManager::startEnroll(const std::string& finger) {
  if (busy()) {
    return;
  }
  m_mode = Mode::Enrolling;
  m_enrollFinger = finger;
  m_stagesDone = 0;
  m_stagesTotal = -1;
  m_enrollCompleted = false;
  m_matchedFinger.clear();
  setStatus(i18n::tr("settings.fingerprint.status.preparing"), false);

  claimThen([this, finger]() {
    try {
      m_stagesTotal = m_device->getProperty("num-enroll-stages").onInterface(kDeviceInterface).get<std::int32_t>();
    } catch (const sdbus::Error& e) {
      kLog.debug("could not read num-enroll-stages: {}", e.what());
      m_stagesTotal = -1;
    }
    m_device->callMethodAsync("EnrollStart")
        .onInterface(kDeviceInterface)
        .withTimeout(kInteractiveTimeout)
        .withArguments(finger)
        .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive)](std::optional<sdbus::Error> e) {
          if (alive.expired()) {
            return;
          }
          if (e.has_value()) {
            kLog.info("could not start enrollment: {}", e->what());
            setStatus(errorMessage(*e), true);
            finishOperation();
            return;
          }
          if (m_mode == Mode::Enrolling) {
            setStatus(touchPrompt(m_devices, m_selectedPath), false);
          }
        });
  });
  notifyChanged();
}

void FingerprintManager::handleEnrollStatus(const std::string& result, bool done) {
  if (m_mode != Mode::Enrolling) {
    return;
  }
  kLog.debug("enroll status: {} (done={})", result, done);
  constexpr std::string_view kPrefix = "enroll-";
  const std::string_view suffix =
      std::string_view(result).starts_with(kPrefix) ? std::string_view(result).substr(kPrefix.size()) : result;

  if (suffix == "completed") {
    m_enrollCompleted = true;
    if (m_stagesTotal > 0) {
      m_stagesDone = m_stagesTotal;
    }
    if (!std::ranges::contains(m_enrolled, m_enrollFinger)) {
      m_enrolled.push_back(m_enrollFinger);
    }
    setStatus(i18n::tr("settings.fingerprint.status.enroll-completed"), false);
  } else if (suffix == "stage-passed") {
    ++m_stagesDone;
    setStatus(i18n::tr("settings.fingerprint.status.stage-passed"), false);
  } else if (const auto retry = retryMessage(suffix)) {
    setStatus(*retry, false);
  } else if (suffix == "duplicate") {
    setStatus(i18n::tr("settings.fingerprint.status.duplicate"), true);
  } else if (suffix == "data-full") {
    setStatus(i18n::tr("settings.fingerprint.status.data-full"), true);
  } else if (suffix == "disconnected") {
    setStatus(i18n::tr("settings.fingerprint.status.disconnected"), true);
  } else {
    // enroll-failed, enroll-unknown-error and anything newer than this code.
    setStatus(i18n::tr("settings.fingerprint.status.enroll-failed"), true);
  }

  if (!done) {
    notifyChanged();
    return;
  }
  if (m_device != nullptr) {
    m_device->callMethodAsync("EnrollStop")
        .onInterface(kDeviceInterface)
        .uponReplyInvoke([](std::optional<sdbus::Error>) {});
  }
  finishOperation();
}

void FingerprintManager::startVerify() {
  if (busy()) {
    return;
  }
  m_mode = Mode::Verifying;
  m_matchedFinger.clear();
  m_enrollCompleted = false;
  setStatus(i18n::tr("settings.fingerprint.status.preparing"), false);

  claimThen([this]() {
    m_device->callMethodAsync("VerifyStart")
        .onInterface(kDeviceInterface)
        .withTimeout(kInteractiveTimeout)
        .withArguments(std::string{"any"})
        .uponReplyInvoke([this, alive = std::weak_ptr<void>(m_alive)](std::optional<sdbus::Error> e) {
          if (alive.expired()) {
            return;
          }
          if (e.has_value()) {
            kLog.info("could not start verification: {}", e->what());
            setStatus(errorMessage(*e), true);
            finishOperation();
            return;
          }
          if (m_mode != Mode::Verifying) {
            return;
          }
          setStatus(touchPrompt(m_devices, m_selectedPath), false);
          m_verifyTimeout.start(kVerifyTimeout, [this]() {
            if (m_mode != Mode::Verifying) {
              return;
            }
            cancel();
            setStatus(i18n::tr("settings.fingerprint.status.verify-timeout"), true);
          });
        });
  });
  notifyChanged();
}

void FingerprintManager::handleVerifyStatus(const std::string& result, bool done) {
  if (m_mode != Mode::Verifying) {
    return;
  }
  kLog.debug("verify status: {} (done={})", result, done);
  constexpr std::string_view kPrefix = "verify-";
  const std::string_view suffix =
      std::string_view(result).starts_with(kPrefix) ? std::string_view(result).substr(kPrefix.size()) : result;

  if (suffix == "match") {
    if (m_matchedFinger.empty()) {
      m_matchedFinger = "any";
    }
    if (m_matchedFinger == "any") {
      setStatus(i18n::tr("settings.fingerprint.status.match"), false);
    } else {
      setStatus(i18n::tr("settings.fingerprint.status.match-finger", "finger", fingerLabel(m_matchedFinger)), false);
    }
  } else if (suffix == "no-match") {
    m_matchedFinger.clear();
    setStatus(i18n::tr("settings.fingerprint.status.no-match"), true);
  } else if (const auto retry = retryMessage(suffix)) {
    setStatus(*retry, false);
  } else if (suffix == "disconnected") {
    m_matchedFinger.clear();
    setStatus(i18n::tr("settings.fingerprint.status.disconnected"), true);
  } else {
    m_matchedFinger.clear();
    setStatus(i18n::tr("settings.fingerprint.status.verify-failed"), true);
  }

  if (!done) {
    notifyChanged();
    return;
  }
  if (m_device != nullptr) {
    m_device->callMethodAsync("VerifyStop")
        .onInterface(kDeviceInterface)
        .uponReplyInvoke([](std::optional<sdbus::Error>) {});
  }
  finishOperation();
}

void FingerprintManager::cancel() {
  if (m_mode == Mode::Idle && !m_claiming) {
    return;
  }
  const Mode mode = m_mode;
  m_verifyTimeout.stop();
  m_mode = Mode::Idle;
  if (m_device != nullptr && m_claimed) {
    const char* stop = mode == Mode::Enrolling ? "EnrollStop" : "VerifyStop";
    m_device->callMethodAsync(stop).onInterface(kDeviceInterface).uponReplyInvoke([](std::optional<sdbus::Error>) {});
  }
  release();
  if (mode == Mode::Enrolling && !m_enrollCompleted) {
    m_enrollFinger.clear();
  }
  clearStatus();
  notifyChanged();
}

void FingerprintManager::clearStatus() {
  m_status.clear();
  m_statusError = false;
  m_matchedFinger.clear();
}

void FingerprintManager::resetEnrollment() {
  if (m_mode == Mode::Enrolling) {
    return;
  }
  m_enrollFinger.clear();
  m_stagesDone = 0;
  m_stagesTotal = -1;
  m_enrollCompleted = false;
  clearStatus();
}

void FingerprintManager::setStatus(std::string message, bool error) {
  m_status = std::move(message);
  m_statusError = error;
  notifyChanged();
}

void FingerprintManager::notifyChanged() {
  if (m_onChanged) {
    m_onChanged();
  }
}

const std::vector<std::string>& FingerprintManager::selectableFingers() {
  static const std::vector<std::string> kFingers = {
      "right-thumb", "right-index-finger", "right-middle-finger",
      "left-thumb",  "left-index-finger",  "left-middle-finger",
  };
  return kFingers;
}

std::string FingerprintManager::fingerLabel(std::string_view finger) {
  static const std::map<std::string, std::string, std::less<>> kKeys = {
      {"left-thumb", "settings.fingerprint.finger.left-thumb"},
      {"left-index-finger", "settings.fingerprint.finger.left-index"},
      {"left-middle-finger", "settings.fingerprint.finger.left-middle"},
      {"left-ring-finger", "settings.fingerprint.finger.left-ring"},
      {"left-little-finger", "settings.fingerprint.finger.left-little"},
      {"right-thumb", "settings.fingerprint.finger.right-thumb"},
      {"right-index-finger", "settings.fingerprint.finger.right-index"},
      {"right-middle-finger", "settings.fingerprint.finger.right-middle"},
      {"right-ring-finger", "settings.fingerprint.finger.right-ring"},
      {"right-little-finger", "settings.fingerprint.finger.right-little"},
  };
  const auto it = kKeys.find(finger);
  return it == kKeys.end() ? std::string(finger) : i18n::tr(it->second);
}
