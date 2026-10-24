#include "security/security_key_manager.h"

#include "auth/security_key_authenticator.h"
#include "core/deferred_call.h"
#include "core/log.h"
#include "core/process/process.h"
#include "i18n/i18n.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <pwd.h>
#include <string_view>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace {
  constexpr Logger kLog("security-keys");

  constexpr int kCommandTimeoutSeconds = 20;
  // pamu2fcfg waits for a touch; give the user time to find the key.
  constexpr int kRegisterTimeoutSeconds = 60;
  constexpr int kNetworkTimeoutSeconds = 60;

  std::vector<std::string> split(std::string_view text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
      const std::size_t end = text.find(separator, start);
      parts.emplace_back(text.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start));
      if (end == std::string_view::npos) {
        return parts;
      }
      start = end + 1;
    }
  }

  std::vector<std::string> lines(std::string_view text) {
    std::vector<std::string> out;
    for (auto& line : split(text, '\n')) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      if (!line.empty()) {
        out.push_back(std::move(line));
      }
    }
    return out;
  }

  // gpg --with-colons escapes ':' and control characters as C-style "\xHH".
  std::string unescapeColons(std::string_view field) {
    std::string out;
    out.reserve(field.size());
    for (std::size_t i = 0; i < field.size(); ++i) {
      if (field[i] == '\\' && i + 3 < field.size() && field[i + 1] == 'x') {
        const std::string hex(field.substr(i + 2, 2));
        char* end = nullptr;
        const long value = std::strtol(hex.c_str(), &end, 16);
        if (end != nullptr && *end == '\0' && hex.size() == 2) {
          out.push_back(static_cast<char>(value));
          i += 3;
          continue;
        }
      }
      out.push_back(field[i]);
    }
    return out;
  }

  std::string field(const std::vector<std::string>& fields, std::size_t index) {
    return index < fields.size() ? unescapeColons(fields[index]) : std::string{};
  }

  std::string currentUserName() {
    if (const passwd* pw = ::getpwuid(::getuid()); pw != nullptr && pw->pw_name != nullptr) {
      return pw->pw_name;
    }
    if (const char* user = std::getenv("USER"); user != nullptr) {
      return user;
    }
    return {};
  }

  // Last meaningful stderr line, for error messages.
  std::string lastLine(std::string_view text) {
    const auto all = lines(text);
    return all.empty() ? std::string{} : all.back();
  }
} // namespace

SecurityKeyManager::SecurityKeyManager() : m_user(currentUserName()) {}

SecurityKeyManager::~SecurityKeyManager() {
  m_alive.reset();
  if (m_registerCancel) {
    m_registerCancel->store(true);
  }
  if (m_tester != nullptr) {
    m_tester->stop();
  }
}

void SecurityKeyManager::setChangedCallback(ChangedCallback callback) { m_onChanged = std::move(callback); }

bool SecurityKeyManager::fido2ToolsAvailable() { return process::commandExists("pamu2fcfg"); }

bool SecurityKeyManager::gpgAvailable() { return process::commandExists("gpg"); }

bool SecurityKeyManager::testServiceAvailable() {
  std::error_code ec;
  return std::filesystem::exists("/etc/pam.d/noctalia-lock-u2f", ec)
      || std::filesystem::exists("/usr/lib/pam.d/noctalia-lock-u2f", ec);
}

std::filesystem::path SecurityKeyManager::authfilePath() {
  // Same lookup as pam_u2f's default authfile.
  std::filesystem::path base;
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg != nullptr && *xdg != '\0') {
    base = xdg;
  } else if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    base = std::filesystem::path(home) / ".config";
  } else if (const passwd* pw = ::getpwuid(::getuid()); pw != nullptr && pw->pw_dir != nullptr) {
    base = std::filesystem::path(pw->pw_dir) / ".config";
  }
  return base / "Yubico" / "u2f_keys";
}

bool SecurityKeyManager::run(
    std::vector<std::string> args, ResultHandler done, std::optional<std::string> stdinData,
    std::shared_ptr<std::atomic<bool>> cancel, std::optional<int> timeoutSeconds
) {
  process::RunOptions options;
  options.timeout = std::chrono::seconds(timeoutSeconds.value_or(kCommandTimeoutSeconds));
  options.maxOutputBytes = 1024 * 1024;
  options.cancel = std::move(cancel);
  options.stdinData = std::move(stdinData);
  // Untranslated output: it is parsed.
  options.env.push_back({.name = "LC_ALL", .value = "C"});
  return process::runAsync(
      args,
      process::RunCallbacks{
          .stdOut = {},
          .stdErr = {},
          .onExit =
              [alive = std::weak_ptr<void>(m_alive), done = std::move(done)](process::RunResult result) {
                DeferredCall::callLater([alive, done, result = std::move(result)]() {
                  if (!alive.expired()) {
                    done(result);
                  }
                });
              },
      },
      std::move(options)
  );
}

void SecurityKeyManager::refresh() {
  m_loaded = true;
  if (fido2ToolsAvailable()) {
    loadConnectedKeys();
    loadCredentials();
  }
  if (gpgAvailable() && !m_gpgBusy) {
    loadCard();
  }
  notifyChanged();
}

void SecurityKeyManager::loadConnectedKeys() {
  if (process::commandExists("fido2-token")) {
    // "/dev/hidraw4: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)"
    (void)run({"fido2-token", "-L"}, [this](const process::RunResult& result) {
      m_connectedKeys.clear();
      for (const auto& line : lines(result.out)) {
        const auto open = line.find('(');
        const auto close = line.rfind(')');
        if (open != std::string::npos && close != std::string::npos && close > open) {
          m_connectedKeys.push_back(line.substr(open + 1, close - open - 1));
        } else {
          m_connectedKeys.push_back(line);
        }
      }
      notifyChanged();
    });
    return;
  }
  if (process::commandExists("ykman")) {
    // "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678"
    (void)run({"ykman", "list"}, [this](const process::RunResult& result) {
      m_connectedKeys = result ? lines(result.out) : std::vector<std::string>{};
      notifyChanged();
    });
  }
}

void SecurityKeyManager::loadCredentials() {
  m_credentials.clear();
  std::ifstream in(authfilePath());
  std::string line;
  const std::string prefix = m_user + ":";
  while (std::getline(in, line)) {
    if (!line.starts_with(prefix)) {
      continue;
    }
    // user:KeyHandle,PublicKey,CoseType,Options[:KeyHandle2,...]
    for (auto& cred : split(std::string_view(line).substr(prefix.size()), ':')) {
      if (cred.empty()) {
        continue;
      }
      const auto comma = cred.find(',');
      m_credentials.push_back(Credential{.keyHandle = cred.substr(0, comma), .raw = cred});
    }
  }
}

bool SecurityKeyManager::writeCredentials(const std::vector<std::string>& creds) {
  const auto path = authfilePath();
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    kLog.warn("could not create {}: {}", path.parent_path().string(), ec.message());
    return false;
  }

  std::vector<std::string> kept;
  bool replaced = false;
  std::string joined = m_user;
  for (const auto& cred : creds) {
    joined += ":" + cred;
  }
  {
    std::ifstream in(path);
    std::string line;
    const std::string prefix = m_user + ":";
    while (std::getline(in, line)) {
      if (line.starts_with(prefix)) {
        if (!replaced && !creds.empty()) {
          kept.push_back(joined);
        }
        replaced = true;
        continue;
      }
      if (!line.empty()) {
        kept.push_back(line);
      }
    }
  }
  if (!replaced && !creds.empty()) {
    kept.push_back(joined);
  }

  // Write a private temp file next to the authfile, then rename over it.
  const auto tmp = path.parent_path() / (path.filename().string() + ".tmp");
  {
    const mode_t oldMask = ::umask(077);
    std::ofstream out(tmp, std::ios::trunc);
    ::umask(oldMask);
    for (const auto& line : kept) {
      out << line << '\n';
    }
    out.flush();
    if (!out) {
      kLog.warn("could not write {}", tmp.string());
      std::filesystem::remove(tmp, ec);
      return false;
    }
  }
  std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec);
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    kLog.warn("could not replace {}: {}", path.string(), ec.message());
    std::filesystem::remove(tmp, ec);
    return false;
  }
  return true;
}

void SecurityKeyManager::startRegister(std::string pin) {
  if (m_registering || m_user.empty()) {
    return;
  }
  m_registering = true;
  m_registerResult.reset();
  m_registerCancel = std::make_shared<std::atomic<bool>>(false);
  setFidoStatus(i18n::tr("settings.security-keys.fido.status.touch"), false);

  std::optional<std::string> stdinData;
  if (!pin.empty()) {
    // Without a terminal, pamu2fcfg reads the PIN from stdin.
    stdinData = pin + "\n";
  }
  const bool started = run(
      {"pamu2fcfg", "-u", m_user},
      [this](const process::RunResult& result) {
        m_registering = false;
        const bool cancelled = m_registerCancel && m_registerCancel->load();
        m_registerCancel.reset();
        if (cancelled) {
          m_fidoStatus.clear();
          notifyChanged();
          return;
        }
        // Output: "user:KeyHandle,PublicKey,CoseType,Options"
        const std::string out = lastLine(result.out);
        const auto colon = out.find(':');
        if (!result || colon == std::string::npos || colon + 1 >= out.size()) {
          m_registerResult = false;
          const std::string err = result.err;
          if (result.timedOut) {
            setFidoStatus(i18n::tr("settings.security-keys.fido.status.timeout"), true);
          } else if (err.find("PIN") != std::string::npos) {
            setFidoStatus(i18n::tr("settings.security-keys.fido.status.pin-required"), true);
          } else if (err.find("No device") != std::string::npos || err.find("No FIDO") != std::string::npos) {
            setFidoStatus(i18n::tr("settings.security-keys.fido.status.no-device"), true);
          } else {
            setFidoStatus(
                i18n::tr("settings.security-keys.fido.status.register-failed", "message", lastLine(err)), true
            );
          }
          return;
        }

        std::vector<std::string> creds;
        for (const auto& cred : m_credentials) {
          creds.push_back(cred.raw);
        }
        creds.push_back(out.substr(colon + 1));
        if (!writeCredentials(creds)) {
          m_registerResult = false;
          setFidoStatus(
              i18n::tr("settings.security-keys.fido.status.write-failed", "path", authfilePath().string()), true
          );
          return;
        }
        loadCredentials();
        m_registerResult = true;
        setFidoStatus(i18n::tr("settings.security-keys.fido.status.registered"), false);
      },
      std::move(stdinData), m_registerCancel, kRegisterTimeoutSeconds
  );
  if (!started) {
    m_registering = false;
    m_registerResult = false;
    setFidoStatus(i18n::tr("settings.security-keys.fido.status.register-failed", "message", "pamu2fcfg"), true);
  }
}

void SecurityKeyManager::cancelRegister() {
  if (m_registerCancel) {
    m_registerCancel->store(true);
  }
}

void SecurityKeyManager::clearRegisterResult() {
  m_registerResult.reset();
  if (!m_registering && !m_testing) {
    m_fidoStatus.clear();
    m_fidoStatusError = false;
  }
}

void SecurityKeyManager::removeCredential(std::size_t index) {
  if (index >= m_credentials.size() || m_registering) {
    return;
  }
  std::vector<std::string> creds;
  for (std::size_t i = 0; i < m_credentials.size(); ++i) {
    if (i != index) {
      creds.push_back(m_credentials[i].raw);
    }
  }
  if (!writeCredentials(creds)) {
    setFidoStatus(i18n::tr("settings.security-keys.fido.status.write-failed", "path", authfilePath().string()), true);
    return;
  }
  loadCredentials();
  setFidoStatus(i18n::tr("settings.security-keys.fido.status.removed"), false);
}

void SecurityKeyManager::startTest() {
  if (m_testing || m_registering) {
    return;
  }
  if (m_tester == nullptr) {
    m_tester = std::make_unique<SecurityKeyAuthenticator>();
    m_tester->setCueCallback([this]() { setFidoStatus(i18n::tr("settings.security-keys.fido.status.touch"), false); });
    m_tester->setAuthenticatedCallback([this]() {
      m_testing = false;
      setFidoStatus(i18n::tr("settings.security-keys.fido.status.test-ok"), false);
    });
    m_tester->setGaveUpCallback([this](bool cued) {
      m_testing = false;
      setFidoStatus(
          i18n::tr(
              cued ? "settings.security-keys.fido.status.test-timeout"
                   : "settings.security-keys.fido.status.test-no-key"
          ),
          true
      );
    });
  }
  m_testing = true;
  setFidoStatus(i18n::tr("settings.security-keys.fido.status.testing"), false);
  m_tester->start(false);
}

void SecurityKeyManager::stopTest() {
  if (!m_testing) {
    return;
  }
  m_testing = false;
  if (m_tester != nullptr) {
    m_tester->stop();
  }
  m_fidoStatus.clear();
  m_fidoStatusError = false;
  notifyChanged();
}

void SecurityKeyManager::loadCard() {
  m_gpgBusy = true;
  const bool started = run({"gpg", "--card-status", "--with-colons"}, [this](const process::RunResult& result) {
    m_gpgBusy = false;
    if (!result) {
      m_card.reset();
      m_keyState = KeyState::Unknown;
      m_trusted = false;
      notifyChanged();
      return;
    }
    CardInfo card;
    for (const auto& line : lines(result.out)) {
      const auto fields = split(line, ':');
      const std::string& kind = fields.front();
      if (kind == "Reader") {
        card.reader = field(fields, 1);
      } else if (kind == "vendor") {
        card.vendor = field(fields, 2);
      } else if (kind == "serial") {
        card.serial = field(fields, 1);
      } else if (kind == "name") {
        card.holder = field(fields, 1);
        const std::string last = field(fields, 2);
        if (!last.empty()) {
          card.holder += card.holder.empty() ? last : " " + last;
        }
      } else if (kind == "url") {
        card.url = field(fields, 1);
      } else if (kind == "fpr") {
        for (std::size_t i = 1; i <= 3; ++i) {
          std::string fpr = field(fields, i);
          if (!fpr.empty()) {
            if (i == 1) {
              card.signatureFingerprint = fpr;
            }
            card.fingerprints.push_back(std::move(fpr));
          }
        }
      }
    }
    m_card = std::move(card);
    loadKeyState();
  });
  if (!started) {
    m_gpgBusy = false;
  }
}

void SecurityKeyManager::loadKeyState() {
  if (!m_card.has_value() || m_card->fingerprints.empty()) {
    m_keyState = KeyState::Unknown;
    m_trusted = false;
    notifyChanged();
    return;
  }
  const std::string fpr = m_card->fingerprints.front();
  (void)run({"gpg", "--list-secret-keys", "--with-colons", fpr}, [this, fpr](const process::RunResult& secret) {
    if (!m_card.has_value()) {
      return;
    }
    // A key on a card shows the card serial in field 15 of its sec/ssb record.
    bool onCard = false;
    std::string serial;
    for (const auto& line : lines(secret.out)) {
      const auto fields = split(line, ':');
      if (fields.front() == "sec" || fields.front() == "ssb") {
        serial = field(fields, 14);
      } else if (fields.front() == "fpr" && std::ranges::contains(m_card->fingerprints, field(fields, 9))) {
        if (!serial.empty() && serial != "#") {
          onCard = true;
        }
      }
    }
    (void)run({"gpg", "--list-keys", "--with-colons", fpr}, [this, onCard](const process::RunResult& pub) {
      m_trusted = false;
      m_primaryFingerprint.clear();
      bool afterPub = false;
      for (const auto& line : lines(pub.out)) {
        const auto fields = split(line, ':');
        if (fields.front() == "pub") {
          m_trusted = field(fields, 8) == "u";
          afterPub = true;
        } else if (fields.front() == "fpr" && afterPub) {
          m_primaryFingerprint = field(fields, 9);
          afterPub = false;
        }
      }
      if (!pub) {
        m_keyState = KeyState::Missing;
      } else {
        m_keyState = onCard ? KeyState::Ready : KeyState::PublicOnly;
      }
      notifyChanged();
    });
  });
}

void SecurityKeyManager::importPublicKey(bool offline) {
  if (m_gpgBusy || !m_card.has_value()) {
    return;
  }
  if (offline) {
    setGpgStatus(i18n::tr("settings.security-keys.gpg.status.offline"), true);
    return;
  }
  m_gpgBusy = true;
  if (m_card->url.empty()) {
    importFromKeyserver();
    return;
  }
  setGpgStatus(i18n::tr("settings.security-keys.gpg.status.fetching-url"), false);
  const bool started = run(
      {"gpg", "--fetch-keys", m_card->url},
      [this](const process::RunResult& result) {
        if (result) {
          createStubs(i18n::tr("settings.security-keys.gpg.status.imported"));
          return;
        }
        kLog.info("gpg --fetch-keys failed: {}", lastLine(result.err));
        importFromKeyserver();
      },
      std::nullopt, nullptr, kNetworkTimeoutSeconds
  );
  if (!started) {
    importFromKeyserver();
  }
}

void SecurityKeyManager::importFromKeyserver() {
  if (!m_card.has_value() || m_card->fingerprints.empty()) {
    m_gpgBusy = false;
    setGpgStatus(i18n::tr("settings.security-keys.gpg.status.import-failed"), true);
    return;
  }
  setGpgStatus(i18n::tr("settings.security-keys.gpg.status.fetching-keyserver"), false);
  // Uses the keyserver configured for gpg/dirmngr.
  const bool started = run(
      {"gpg", "--recv-keys", m_card->fingerprints.front()},
      [this](const process::RunResult& result) {
        if (result) {
          createStubs(i18n::tr("settings.security-keys.gpg.status.imported"));
          return;
        }
        kLog.info("gpg --recv-keys failed: {}", lastLine(result.err));
        m_gpgBusy = false;
        setGpgStatus(i18n::tr("settings.security-keys.gpg.status.import-failed"), true);
      },
      std::nullopt, nullptr, kNetworkTimeoutSeconds
  );
  if (!started) {
    m_gpgBusy = false;
    setGpgStatus(i18n::tr("settings.security-keys.gpg.status.import-failed"), true);
  }
}

void SecurityKeyManager::importPublicKeyFromFile(const std::filesystem::path& file) {
  if (m_gpgBusy) {
    return;
  }
  m_gpgBusy = true;
  setGpgStatus(i18n::tr("settings.security-keys.gpg.status.importing-file"), false);
  const bool started = run({"gpg", "--import", file.string()}, [this](const process::RunResult& result) {
    if (result) {
      createStubs(i18n::tr("settings.security-keys.gpg.status.imported"));
      return;
    }
    m_gpgBusy = false;
    setGpgStatus(
        i18n::tr("settings.security-keys.gpg.status.import-file-failed", "message", lastLine(result.err)), true
    );
  });
  if (!started) {
    m_gpgBusy = false;
  }
}

void SecurityKeyManager::createStubs(std::string successMessage) {
  // Reading the card with the public key in the keyring links the secret-key stubs to it.
  (void)run({"gpg", "--card-status"}, [this, successMessage = std::move(successMessage)](const process::RunResult&) {
    m_gpgBusy = false;
    setGpgStatus(successMessage, false);
    loadCard();
  });
}

void SecurityKeyManager::trustKey() {
  if (m_gpgBusy || m_primaryFingerprint.empty()) {
    return;
  }
  m_gpgBusy = true;
  const bool started = run(
      {"gpg", "--import-ownertrust"},
      [this](const process::RunResult& result) {
        m_gpgBusy = false;
        if (result) {
          setGpgStatus(i18n::tr("settings.security-keys.gpg.status.trusted"), false);
        } else {
          setGpgStatus(
              i18n::tr("settings.security-keys.gpg.status.trust-failed", "message", lastLine(result.err)), true
          );
        }
        loadKeyState();
      },
      m_primaryFingerprint + ":6:\n"
  );
  if (!started) {
    m_gpgBusy = false;
  }
}

void SecurityKeyManager::setFidoStatus(std::string message, bool error) {
  m_fidoStatus = std::move(message);
  m_fidoStatusError = error;
  notifyChanged();
}

void SecurityKeyManager::setGpgStatus(std::string message, bool error) {
  m_gpgStatus = std::move(message);
  m_gpgStatusError = error;
  notifyChanged();
}

void SecurityKeyManager::notifyChanged() {
  if (m_onChanged) {
    m_onChanged();
  }
}
