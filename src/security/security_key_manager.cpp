#include "security/security_key_manager.h"

#include "auth/security_key_authenticator.h"
#include "core/deferred_call.h"
#include "core/log.h"
#include "i18n/i18n.h"
#include "util/base64.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <pwd.h>
#include <sodium.h>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace {
  constexpr Logger kLog("security-keys");

  constexpr int kProbeTimeoutSeconds = 10;
  constexpr int kGpgTimeoutSeconds = 30;
  // pamu2fcfg waits for a touch; give the user time to find the key.
  constexpr int kTouchTimeoutSeconds = 60;
  constexpr int kNetworkTimeoutSeconds = 45;
  constexpr auto kProbeInterval = std::chrono::seconds(2);

  // The services whose pam_u2f lines say where keys must be registered.
  constexpr std::array<std::string_view, 2> kPamServices{"sudo", "polkit-1"};
  constexpr std::array<std::string_view, 2> kPamDirs{"/etc/pam.d", "/usr/lib/pam.d"};

  using security_hw::lastLine;
  using security_hw::splitLines;

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

  bool isHexFingerprint(std::string_view text) {
    return (text.size() == 40 || text.size() == 64) && std::ranges::all_of(text, [](char c) {
             return std::isxdigit(static_cast<unsigned char>(c)) != 0;
           });
  }

  std::string currentUserName() {
    if (const char* user = std::getenv("USER"); user != nullptr && *user != '\0') {
      return user;
    }
    if (const passwd* pw = ::getpwuid(::getuid()); pw != nullptr && pw->pw_name != nullptr) {
      return pw->pw_name;
    }
    return {};
  }

  std::string hostName() {
    std::array<char, 256> buffer{};
    if (::gethostname(buffer.data(), buffer.size() - 1) != 0) {
      return {};
    }
    return buffer.data();
  }

  std::filesystem::path pamFile(std::string_view service) {
    std::error_code ec;
    for (const auto dir : kPamDirs) {
      const auto path = std::filesystem::path(dir) / service;
      if (std::filesystem::is_regular_file(path, ec)) {
        return path;
      }
    }
    return {};
  }

  std::string readSmallFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::stringstream text;
    text << in.rdbuf();
    return text.str();
  }

  std::string errorKey(std::string_view code) { return "settings.security-keys.error." + std::string(code); }

  bool knownError(std::string_view code) {
    static constexpr std::array<std::string_view, 34> kKnown{
        "pin-required",   "pin-invalid",        "pin-blocked",     "timeout",           "no-device",
        "no-card",        "no-pin",             "already-registered", "not-target",     "write-failed",
        "test-failed",    "test-no-key",        "import-failed",   "import-file-failed", "trust-failed",
        "remove-failed",  "secret-on-disk",     "ssh-none",        "ssh-exists",        "ssh-file-exists",
        "ssh-not-on-key", "ssh-encrypted",      "ssh-damaged",     "ssh-invalid",       "ssh-config-edited",
        "ssh-config-foreign", "ssh-config-link", "ssh-config-conflict", "offline",      "workdir",
        "no-key",         "start-failed",       "no-file",         "generic",
    };
    return std::ranges::contains(kKnown, code);
  }
} // namespace

SecurityKeyManager::SecurityKeyManager() : m_user(currentUserName()) {}

SecurityKeyManager::~SecurityKeyManager() {
  m_alive.reset();
  m_probeTimer.stop();
  if (m_opCancel) {
    m_opCancel->store(true);
  }
  if (m_tester != nullptr) {
    m_tester->stop();
  }
  if (m_workdir.has_value()) {
    std::error_code ec;
    std::filesystem::remove_all(*m_workdir, ec);
  }
}

void SecurityKeyManager::setChangedCallback(ChangedCallback callback) { m_onChanged = std::move(callback); }

bool SecurityKeyManager::fido2ToolsAvailable() {
  return process::commandExists("pamu2fcfg") && process::commandExists("fido2-token");
}

bool SecurityKeyManager::gpgAvailable() { return process::commandExists("gpg"); }

bool SecurityKeyManager::sshAvailable() {
  return process::commandExists("ssh-keygen") && process::commandExists("fido2-token");
}

bool SecurityKeyManager::testServiceAvailable() { return !pamFile("noctalia-lock-u2f").empty(); }

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

bool SecurityKeyManager::run(std::vector<std::string> args, ResultHandler done, RunExtras extras) {
  process::RunOptions options;
  options.timeout = std::chrono::seconds(extras.timeoutSeconds);
  options.maxOutputBytes = 1024 * 1024;
  options.cancel = m_opCancel;
  options.stdinData = std::move(extras.stdinData);
  options.workingDir = std::move(extras.workingDir);
  options.env = std::move(extras.env);
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

// -- Operations ---------------------------------------------------------------------------------

bool SecurityKeyManager::beginOp(Op op, Area area) {
  if (m_op != Op::None || m_tester != nullptr) {
    return false;
  }
  m_op = op;
  m_opArea = area;
  m_stage.clear();
  m_opCancel = std::make_shared<std::atomic<bool>>(false);
  clearStatus(area);
  return true;
}

void SecurityKeyManager::finishOp() {
  m_op = Op::None;
  m_stage.clear();
  m_opCancel.reset();
  if (m_workdir.has_value()) {
    std::error_code ec;
    std::filesystem::remove_all(*m_workdir, ec);
    m_workdir.reset();
  }
  notifyChanged();
}

bool SecurityKeyManager::cancelled() const { return m_opCancel == nullptr || m_opCancel->load(); }

void SecurityKeyManager::cancel() {
  if (m_tester != nullptr) {
    m_tester->stop();
    m_tester.reset();
    finishOp();
    return;
  }
  if (m_opCancel) {
    m_opCancel->store(true);
  }
}

void SecurityKeyManager::setStage(std::string stage) {
  m_stage = std::move(stage);
  notifyChanged();
}

const SecurityKeyManager::Status& SecurityKeyManager::status(Area area) const {
  return const_cast<SecurityKeyManager*>(this)->statusRef(area);
}

SecurityKeyManager::Status& SecurityKeyManager::statusRef(Area area) {
  switch (area) {
  case Area::Fido:
    return m_fidoStatus;
  case Area::Gpg:
    return m_gpgStatus;
  case Area::Ssh:
    break;
  }
  return m_sshStatus;
}

void SecurityKeyManager::setStatus(Area area, std::string message, bool error) {
  statusRef(area) = {.message = std::move(message), .error = error};
  notifyChanged();
}

void SecurityKeyManager::clearStatus(Area area) {
  statusRef(area) = {};
  notifyChanged();
}

void SecurityKeyManager::succeed(Area area, std::string message) {
  statusRef(area) = {.message = std::move(message), .error = false};
}

void SecurityKeyManager::fail(Area area, const std::string& code, const std::string& detail) {
  const std::string key = errorKey(knownError(code) ? code : "generic");
  statusRef(area) = {.message = i18n::tr(key, "detail", detail), .error = true};
  if (!detail.empty()) {
    kLog.info("{}: {}", code, detail);
  }
}

bool SecurityKeyManager::reaskPin(Op op, const std::string& code) {
  if (code != "pin-invalid" && code != "pin-required") {
    return false;
  }
  m_pinPrompt = PinPrompt{.op = op, .error = i18n::tr(errorKey(code), "detail", "")};
  return true;
}

void SecurityKeyManager::submitPin(std::string pin) {
  if (!m_pinPrompt.has_value() || busy()) {
    return;
  }
  if (pin.empty()) {
    m_pinPrompt->error = i18n::tr(errorKey("pin-required"), "detail", "");
    notifyChanged();
    return;
  }
  const Op op = m_pinPrompt->op;
  m_pinPrompt.reset();
  startWithPin(op, pin);
  sodium_memzero(pin.data(), pin.size());
}

void SecurityKeyManager::cancelPin() {
  if (!m_pinPrompt.has_value()) {
    return;
  }
  m_pinPrompt.reset();
  notifyChanged();
}

void SecurityKeyManager::startWithPin(Op op, const std::string& pin) {
  switch (op) {
  case Op::FidoRegister:
    runRegister(pin);
    break;
  case Op::SshImport:
    runSshImport(pin);
    break;
  case Op::SshCreate:
    runSshCreate(pin);
    break;
  case Op::SshDelete:
    runSshDelete(pin);
    break;
  default:
    break;
  }
}

// -- State --------------------------------------------------------------------------------------

void SecurityKeyManager::refresh() {
  m_loaded = true;
  if (process::commandExists("fido2-token")) {
    loadDevices();
  }
  loadFidoState();
  if (gpgAvailable()) {
    loadCard();
  }
  loadSsh();
  notifyChanged();
}

void SecurityKeyManager::startWatching() {
  if (!process::commandExists("fido2-token")) {
    return;
  }
  m_probeTimer.startRepeating(kProbeInterval, [this]() { probe(); });
}

void SecurityKeyManager::stopWatching() { m_probeTimer.stop(); }

void SecurityKeyManager::probe() {
  // Not while the PIN is being typed either: a refresh would rebuild the sheet under the cursor.
  if (m_probing || busy() || !m_loaded || m_pinPrompt.has_value()) {
    return;
  }
  m_probing = true;
  const std::uint64_t generation = m_devicesGeneration;
  const bool started = run(
      {"fido2-token", "-L"},
      [this, generation](const process::RunResult& result) {
        m_probing = false;
        if (generation != m_devicesGeneration || busy()) {
          return;
        }
        const auto found = result ? security_hw::parseFidoDevices(result.out) : std::vector<Device>{};
        const bool changed = !std::ranges::equal(found, m_devices, [](const Device& a, const Device& b) {
          return a.path == b.path;
        });
        if (changed) {
          // The OpenPGP card and the resident keys come and go with the key.
          refresh();
        }
      },
      {.timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started) {
    m_probing = false;
  }
}

void SecurityKeyManager::loadDevices(std::function<void()> then) {
  const std::uint64_t generation = ++m_devicesGeneration;
  const bool started = run(
      {"fido2-token", "-L"},
      [this, generation, then](const process::RunResult& result) {
        if (generation != m_devicesGeneration) {
          return;
        }
        auto found = std::make_shared<std::vector<Device>>(
            result ? security_hw::parseFidoDevices(result.out) : std::vector<Device>{}
        );
        loadDeviceInfo(std::move(found), 0, generation, then);
      },
      {.timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started && then) {
    then();
  }
}

void SecurityKeyManager::loadDeviceInfo(
    std::shared_ptr<std::vector<Device>> found, std::size_t index, std::uint64_t generation,
    std::function<void()> then
) {
  if (index >= found->size()) {
    m_devices = std::move(*found);
    notifyChanged();
    if (then) {
      then();
    }
    return;
  }
  const std::string path = (*found)[index].path;
  const bool started = run(
      {"fido2-token", "-I", path},
      [this, found, index, generation, then](const process::RunResult& result) {
        if (generation != m_devicesGeneration) {
          return;
        }
        security_hw::applyFidoInfo((*found)[index], result ? std::string_view(result.out) : std::string_view{});
        loadDeviceInfo(found, index + 1, generation, then);
      },
      {.timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started) {
    loadDeviceInfo(std::move(found), index + 1, generation, std::move(then));
  }
}

// -- FIDO2/U2F ----------------------------------------------------------------------------------

std::vector<std::string> SecurityKeyManager::readOwnCredentials(std::vector<std::string>* others) const {
  std::vector<std::string> mine;
  std::ifstream in(authfilePath());
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.starts_with(m_user + ":")) {
      for (auto& credential : security_hw::credentialHandles(line, m_user)) {
        mine.push_back(std::move(credential));
      }
    } else if (others != nullptr && line.find_first_not_of(" \t") != std::string::npos) {
      others->push_back(line);
    }
  }
  return mine;
}

void SecurityKeyManager::loadFidoState() {
  std::vector<security_hw::PamU2f> services;
  for (const auto service : kPamServices) {
    const auto path = pamFile(service);
    services.push_back(path.empty() ? security_hw::PamU2f{} : security_hw::parsePamU2f(readSmallFile(path)));
  }
  const std::string own = authfilePath().string();
  m_target = security_hw::fidoTarget(services, own);
  m_pinRequired = std::ranges::any_of(services, [](const security_hw::PamU2f& s) { return s.u2f && s.pin; });
  const bool unused = !security_hw::pamUsesFile(services, own, own);

  m_credentials.clear();
  for (const auto& raw : readOwnCredentials(nullptr)) {
    m_credentials.push_back({
        .handle = security_hw::credentialKeyHandle(raw),
        .label = security_hw::credentialLabel(raw),
        .raw = raw,
        .unused = unused,
    });
  }

  m_otherCount = 0;
  if (m_target.kind == security_hw::FidoTargetKind::OtherFile) {
    std::ifstream in(m_target.path);
    if (!in) {
      m_otherCount = -1;
    } else {
      std::string line;
      while (std::getline(in, line)) {
        m_otherCount += static_cast<int>(security_hw::credentialHandles(line, m_user).size());
      }
    }
  }
}

bool SecurityKeyManager::writeCredentials(const std::vector<std::string>& mine, const std::vector<std::string>& others) {
  const auto path = authfilePath();
  const auto dir = path.parent_path();
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    kLog.warn("could not create {}: {}", dir.string(), ec.message());
    return false;
  }
  std::string text;
  for (const auto& line : others) {
    text += line + "\n";
  }
  if (!mine.empty()) {
    text += m_user;
    for (const auto& credential : mine) {
      text += ":" + credential;
    }
    text += "\n";
  }
  // A private temporary file next to the authfile, renamed over it: written whole or not at all.
  std::string tmpl = (dir / ".u2f_keys.XXXXXX").string();
  const int fd = ::mkstemp(tmpl.data());
  if (fd < 0) {
    kLog.warn("could not write {}: {}", path.string(), std::strerror(errno));
    return false;
  }
  bool ok = ::fchmod(fd, 0600) == 0;
  std::size_t written = 0;
  while (ok && written < text.size()) {
    const ssize_t n = ::write(fd, text.data() + written, text.size() - written);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    ok = n > 0;
    written += n > 0 ? static_cast<std::size_t>(n) : 0;
  }
  ok = ok && ::fsync(fd) == 0;
  ::close(fd);
  if (ok) {
    std::filesystem::rename(tmpl, path, ec);
    ok = !ec;
  }
  if (!ok) {
    kLog.warn("could not replace {}", path.string());
    std::filesystem::remove(tmpl, ec);
  }
  return ok;
}

bool SecurityKeyManager::canRegister() const {
  const Device* key = device();
  return key != nullptr && m_target.kind == security_hw::FidoTargetKind::Own && !(m_pinRequired && !key->clientPin);
}

void SecurityKeyManager::requestRegister() {
  if (busy() || !canRegister()) {
    return;
  }
  if (device()->clientPin) {
    m_pinPrompt = PinPrompt{.op = Op::FidoRegister};
    notifyChanged();
    return;
  }
  runRegister({});
}

void SecurityKeyManager::checkAlreadyRegistered(
    std::shared_ptr<std::vector<std::string>> handles, std::size_t index, std::function<void(bool)> then
) {
  if (index >= handles->size() || device() == nullptr || !process::commandExists("fido2-assert")) {
    then(false);
    return;
  }
  // A credential only answers on its own key, and up=false asks for no touch. Anything else
  // (another origin, a key that refuses to answer) just isn't a match.
  std::array<unsigned char, 32> challenge{};
  randombytes_buf(challenge.data(), challenge.size());
  const std::string input = Base64::encode(challenge.data(), challenge.size()) + "\npam://" + hostName() + "\n"
      + (*handles)[index] + "\n";
  const bool started = run(
      {"fido2-assert", "-G", "-t", "up=false", device()->path},
      [this, handles, index, then](const process::RunResult& result) {
        if (cancelled()) {
          then(false);
          return;
        }
        if (result) {
          then(true);
          return;
        }
        checkAlreadyRegistered(handles, index + 1, then);
      },
      {.stdinData = input, .timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started) {
    checkAlreadyRegistered(std::move(handles), index + 1, std::move(then));
  }
}

void SecurityKeyManager::runRegister(const std::string& pin) {
  if (!beginOp(Op::FidoRegister, Area::Fido)) {
    return;
  }
  if (device() == nullptr) {
    fail(Area::Fido, "no-device");
    finishOp();
    return;
  }
  if (m_target.kind != security_hw::FidoTargetKind::Own) {
    fail(Area::Fido, "not-target");
    finishOp();
    return;
  }
  if (m_pinRequired && !device()->clientPin) {
    fail(Area::Fido, "no-pin");
    finishOp();
    return;
  }
  auto handles = std::make_shared<std::vector<std::string>>();
  for (const auto& credential : readOwnCredentials(nullptr)) {
    handles->push_back(security_hw::credentialKeyHandle(credential));
  }
  checkAlreadyRegistered(handles, 0, [this, pin](bool registered) {
    if (cancelled()) {
      finishOp();
      return;
    }
    if (registered) {
      fail(Area::Fido, "already-registered");
      finishOp();
      return;
    }
    setStage("touch");
    std::optional<std::string> input;
    if (!pin.empty()) {
      // Without a terminal, pamu2fcfg reads the PIN from stdin.
      input = pin + "\n";
    }
    const bool first = m_credentials.empty();
    const bool started = run(
        {"pamu2fcfg", "-u", m_user},
        [this, pinGiven = !pin.empty(), first](const process::RunResult& result) {
          if (cancelled()) {
            finishOp();
            return;
          }
          if (!result) {
            const std::string code =
                result.timedOut ? "timeout" : security_hw::fidoErrorCode(result.err, pinGiven);
            if (!reaskPin(Op::FidoRegister, code)) {
              fail(Area::Fido, code, lastLine(result.err));
            }
            finishOp();
            // The key may have been pulled out, or its PIN retries changed.
            loadDevices();
            return;
          }
          const auto added = security_hw::credentialHandles(lastLine(result.out), m_user);
          if (added.empty()) {
            fail(Area::Fido, "generic", "pamu2fcfg");
            finishOp();
            return;
          }
          std::vector<std::string> others;
          const auto mine = readOwnCredentials(&others);
          if (!writeCredentials(security_hw::mergeCredentials(mine, added), others)) {
            fail(Area::Fido, "write-failed", authfilePath().string());
          } else {
            succeed(
                Area::Fido,
                i18n::tr(first ? "settings.security-keys.fido.registered-first" : "settings.security-keys.fido.registered")
            );
          }
          loadFidoState();
          finishOp();
        },
        {.stdinData = std::move(input), .timeoutSeconds = kTouchTimeoutSeconds}
    );
    if (!started) {
      fail(Area::Fido, "start-failed", "pamu2fcfg");
      finishOp();
    }
  });
}

void SecurityKeyManager::removeCredential(const std::string& handle) {
  if (!beginOp(Op::FidoRemove, Area::Fido)) {
    return;
  }
  // By key handle: a list that changed meanwhile can't make it remove another key.
  std::vector<std::string> others;
  const auto mine = readOwnCredentials(&others);
  std::vector<std::string> kept;
  for (const auto& credential : mine) {
    if (security_hw::credentialKeyHandle(credential) != handle) {
      kept.push_back(credential);
    }
  }
  if (handle.empty() || kept.size() == mine.size()) {
    fail(Area::Fido, "remove-failed", handle);
  } else if (!writeCredentials(kept, others)) {
    fail(Area::Fido, "write-failed", authfilePath().string());
  } else {
    succeed(Area::Fido, i18n::tr("settings.security-keys.fido.removed"));
  }
  loadFidoState();
  finishOp();
}

void SecurityKeyManager::startTest() {
  if (!beginOp(Op::FidoTest, Area::Fido)) {
    return;
  }
  // The lock screen's own way in: pam_u2f on the "noctalia-lock-u2f" service.
  m_tester = std::make_unique<SecurityKeyAuthenticator>();
  m_tester->setCueCallback([this]() { setStage("touch"); });
  m_tester->setAuthenticatedCallback([this]() {
    succeed(Area::Fido, i18n::tr("settings.security-keys.fido.test-ok"));
    DeferredCall::callLater([alive = std::weak_ptr<void>(m_alive), this]() {
      if (!alive.expired()) {
        m_tester.reset();
        finishOp();
      }
    });
  });
  m_tester->setGaveUpCallback([this](bool cued) {
    fail(Area::Fido, cued ? "timeout" : "test-no-key");
    DeferredCall::callLater([alive = std::weak_ptr<void>(m_alive), this]() {
      if (!alive.expired()) {
        m_tester.reset();
        finishOp();
      }
    });
  });
  notifyChanged();
  m_tester->start(false);
}

// -- OpenPGP card -------------------------------------------------------------------------------

void SecurityKeyManager::loadCard(std::function<void()> then) {
  m_cardLoading = true;
  const bool started = run(
      {"gpg", "--card-status", "--with-colons"},
      [this, then](const process::RunResult& result) {
        m_cardLoading = false;
        if (!result) {
          m_card.reset();
          m_keyState = KeyState::None;
          m_trusted = false;
          m_primaryFingerprint.clear();
          notifyChanged();
          if (then) {
            then();
          }
          return;
        }
        CardInfo card;
        for (const auto& line : splitLines(result.out)) {
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
            for (std::size_t i = 1; i < fields.size(); ++i) {
              if (isHexFingerprint(fields[i])) {
                card.fingerprints.push_back(fields[i]);
              }
            }
          }
        }
        m_card = std::move(card);
        loadKeyState(then);
      },
      {.timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started) {
    m_cardLoading = false;
    if (then) {
      then();
    }
  }
}

void SecurityKeyManager::loadKeyState(std::function<void()> then) {
  const auto done = [this](const std::function<void()>& next) {
    notifyChanged();
    if (next) {
      next();
    }
  };
  if (!m_card.has_value() || m_card->fingerprints.empty()) {
    m_keyState = KeyState::None;
    m_trusted = false;
    m_primaryFingerprint.clear();
    done(then);
    return;
  }
  const std::string fpr = m_card->fingerprints.front();
  const bool started = run(
      {"gpg", "--list-keys", "--with-colons", fpr},
      [this, fpr, then, done](const process::RunResult& pub) {
        m_trusted = false;
        m_primaryFingerprint.clear();
        if (!pub) {
          m_keyState = KeyState::Missing;
          done(then);
          return;
        }
        bool afterPub = false;
        for (const auto& line : splitLines(pub.out)) {
          const auto fields = split(line, ':');
          if ((fields.front() == "pub" || fields.front() == "sec") && m_primaryFingerprint.empty() && !afterPub) {
            m_trusted = field(fields, 8) == "u";
            afterPub = true;
          } else if (fields.front() == "fpr" && afterPub) {
            m_primaryFingerprint = field(fields, 9);
            break;
          }
        }
        const bool listing = run(
            {"gpg", "--list-secret-keys", "--with-colons", fpr},
            [this, then, done](const process::RunResult& secret) {
              m_keyState = secret && !lastLine(secret.out).empty() ? KeyState::Ready : KeyState::PublicOnly;
              done(then);
            },
            {.timeoutSeconds = kGpgTimeoutSeconds}
        );
        if (!listing) {
          m_keyState = KeyState::PublicOnly;
          done(then);
        }
      },
      {.timeoutSeconds = kGpgTimeoutSeconds}
  );
  if (!started) {
    done(then);
  }
}

void SecurityKeyManager::importPublicKey(bool offline) {
  if (!m_card.has_value() || m_card->fingerprints.empty()) {
    return;
  }
  if (offline) {
    fail(Area::Gpg, "offline");
    notifyChanged();
    return;
  }
  if (!beginOp(Op::GpgImport, Area::Gpg)) {
    return;
  }
  const bool updating = m_keyState == KeyState::Ready;
  setStage("fetch");
  const std::string url = m_card->url;
  if (!(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("hkps://")
        || url.starts_with("hkp://"))) {
    fetchFromKeyserver(updating);
    return;
  }
  const bool started = run(
      {"gpg", "--fetch-keys", url},
      [this, updating](const process::RunResult& result) {
        if (cancelled()) {
          finishOp();
          return;
        }
        if (result) {
          linkCard(i18n::tr(updating ? "settings.security-keys.gpg.updated" : "settings.security-keys.gpg.imported"));
          return;
        }
        kLog.info("gpg --fetch-keys failed: {}", lastLine(result.err));
        fetchFromKeyserver(updating);
      },
      {.timeoutSeconds = kNetworkTimeoutSeconds}
  );
  if (!started) {
    fetchFromKeyserver(updating);
  }
}

void SecurityKeyManager::fetchFromKeyserver(bool updating) {
  if (!m_card.has_value() || m_card->fingerprints.empty()) {
    fail(Area::Gpg, "import-failed");
    finishOp();
    return;
  }
  // The keyserver configured for gpg/dirmngr.
  const bool started = run(
      {"gpg", "--recv-keys", m_card->fingerprints.front()},
      [this, updating](const process::RunResult& result) {
        if (cancelled()) {
          finishOp();
          return;
        }
        if (result) {
          linkCard(i18n::tr(updating ? "settings.security-keys.gpg.updated" : "settings.security-keys.gpg.imported"));
          return;
        }
        kLog.info("gpg --recv-keys failed: {}", lastLine(result.err));
        fail(Area::Gpg, "import-failed");
        finishOp();
        loadCard();
      },
      {.timeoutSeconds = kNetworkTimeoutSeconds}
  );
  if (!started) {
    fail(Area::Gpg, "import-failed");
    finishOp();
  }
}

void SecurityKeyManager::importPublicKeyFromFile(const std::filesystem::path& file) {
  std::error_code ec;
  if (file.empty() || !std::filesystem::is_regular_file(file, ec)) {
    fail(Area::Gpg, "no-file", file.string());
    notifyChanged();
    return;
  }
  if (!beginOp(Op::GpgImportFile, Area::Gpg)) {
    return;
  }
  setStage("import");
  const bool started = run(
      {"gpg", "--batch", "--import", file.string()},
      [this](const process::RunResult& result) {
        if (cancelled()) {
          finishOp();
          return;
        }
        if (result) {
          linkCard(i18n::tr("settings.security-keys.gpg.imported"));
          return;
        }
        fail(Area::Gpg, "import-file-failed", lastLine(result.err));
        finishOp();
      },
      {.timeoutSeconds = kGpgTimeoutSeconds}
  );
  if (!started) {
    fail(Area::Gpg, "start-failed", "gpg");
    finishOp();
  }
}

void SecurityKeyManager::linkCard(std::string message) {
  // Reading the card with the public key in the keyring creates the secret-key stubs that point
  // gpg at it.
  const bool started = run(
      {"gpg", "--card-status"},
      [this, message = std::move(message)](const process::RunResult&) {
        succeed(Area::Gpg, message);
        loadCard([this]() { finishOp(); });
      },
      {.timeoutSeconds = kProbeTimeoutSeconds}
  );
  if (!started) {
    succeed(Area::Gpg, std::move(message));
    finishOp();
  }
}

void SecurityKeyManager::trustKey() {
  if (!beginOp(Op::GpgTrust, Area::Gpg)) {
    return;
  }
  // The card and the key state first: the primary fingerprint comes from the keyring.
  loadCard([this]() {
    if (m_primaryFingerprint.empty()) {
      fail(Area::Gpg, "trust-failed");
      finishOp();
      return;
    }
    const bool started = run(
        {"gpg", "--import-ownertrust"},
        [this](const process::RunResult& result) {
          if (result) {
            succeed(Area::Gpg, i18n::tr("settings.security-keys.gpg.trusted-done"));
          } else {
            fail(Area::Gpg, "trust-failed", lastLine(result.err));
          }
          loadKeyState([this]() { finishOp(); });
        },
        {.stdinData = m_primaryFingerprint + ":6:\n", .timeoutSeconds = kGpgTimeoutSeconds}
    );
    if (!started) {
      fail(Area::Gpg, "trust-failed");
      finishOp();
    }
  });
}

void SecurityKeyManager::removeKey() {
  if (!beginOp(Op::GpgRemove, Area::Gpg)) {
    return;
  }
  loadCard([this]() {
    if (m_primaryFingerprint.empty()) {
      fail(Area::Gpg, "remove-failed", "not in the keyring");
      finishOp();
      return;
    }
    const std::string primary = m_primaryFingerprint;
    const bool started = run(
        {"gpg", "--list-secret-keys", "--with-colons", primary},
        [this, primary](const process::RunResult& secret) {
          const bool hasSecret = secret && !lastLine(secret.out).empty();
          // Only ever stubs: a secret part kept on disk would be lost for good.
          if (hasSecret && security_hw::secretOnDisk(secret.out)) {
            fail(Area::Gpg, "secret-on-disk");
            finishOp();
            return;
          }
          const bool deleting = run(
              {"gpg", "--batch", "--yes", hasSecret ? "--delete-secret-and-public-keys" : "--delete-keys", primary},
              [this](const process::RunResult& result) {
                if (result) {
                  succeed(Area::Gpg, i18n::tr("settings.security-keys.gpg.removed"));
                } else {
                  fail(Area::Gpg, "remove-failed", lastLine(result.err));
                }
                loadCard([this]() { finishOp(); });
              },
              {.timeoutSeconds = kGpgTimeoutSeconds}
          );
          if (!deleting) {
            fail(Area::Gpg, "start-failed", "gpg");
            finishOp();
          }
        },
        {.timeoutSeconds = kGpgTimeoutSeconds}
    );
    if (!started) {
      fail(Area::Gpg, "start-failed", "gpg");
      finishOp();
    }
  });
}

void SecurityKeyManager::notifyChanged() {
  if (m_onChanged) {
    m_onChanged();
  }
}
