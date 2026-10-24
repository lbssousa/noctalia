#pragma once

#include <atomic>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class SecurityKeyAuthenticator;

namespace process {
  struct RunResult;
} // namespace process

// FIDO2/U2F security keys for pam_u2f and the OpenPGP key stored on a smartcard (e.g. a YubiKey).
//
// FIDO2: registers credentials with pamu2fcfg into pam_u2f's default per-user authfile,
// $XDG_CONFIG_HOME/Yubico/u2f_keys, so no privileges are needed. A system that points pam_u2f at
// another authfile must arrange that itself.
//
// OpenPGP: reads the card with gpg, imports its public key (from the URL stored on the card, the
// keyservers configured for gpg, or a file), creates the secret-key stubs and optionally marks
// the key as ultimately trusted.
//
// Commands run off the main thread; results are applied on the main loop. All state lives here
// so the settings page, rebuilt on every change, can stay stateless.
class SecurityKeyManager {
public:
  using ChangedCallback = std::function<void()>;

  struct Credential {
    std::string keyHandle;
    std::string raw;
  };

  struct CardInfo {
    std::string reader;
    std::string vendor;
    std::string serial;
    std::string holder;
    std::string url;
    std::string signatureFingerprint;
    std::vector<std::string> fingerprints; // signature, encryption, authentication (non-empty only)
  };

  enum class KeyState { Unknown, Missing, PublicOnly, Ready };

  SecurityKeyManager();
  ~SecurityKeyManager();

  SecurityKeyManager(const SecurityKeyManager&) = delete;
  SecurityKeyManager& operator=(const SecurityKeyManager&) = delete;

  void setChangedCallback(ChangedCallback callback);

  // pamu2fcfg is required to register FIDO2 keys.
  [[nodiscard]] static bool fido2ToolsAvailable();
  [[nodiscard]] static bool gpgAvailable();
  // The test reuses the lock screen's "noctalia-lock-u2f" PAM service.
  [[nodiscard]] static bool testServiceAvailable();
  [[nodiscard]] static std::filesystem::path authfilePath();

  // Re-reads connected keys, the authfile and the OpenPGP card.
  void refresh();
  [[nodiscard]] bool loaded() const noexcept { return m_loaded; }

  // FIDO2/U2F
  [[nodiscard]] const std::vector<std::string>& connectedKeys() const noexcept { return m_connectedKeys; }
  [[nodiscard]] const std::vector<Credential>& credentials() const noexcept { return m_credentials; }
  void startRegister(std::string pin);
  void cancelRegister();
  [[nodiscard]] bool registering() const noexcept { return m_registering; }
  // Set once the last registration finished: true on success.
  [[nodiscard]] std::optional<bool> registerResult() const noexcept { return m_registerResult; }
  void clearRegisterResult();
  void removeCredential(std::size_t index);
  void startTest();
  void stopTest();
  [[nodiscard]] bool testing() const noexcept { return m_testing; }
  [[nodiscard]] const std::string& fidoStatus() const noexcept { return m_fidoStatus; }
  [[nodiscard]] bool fidoStatusIsError() const noexcept { return m_fidoStatusError; }

  // OpenPGP card
  [[nodiscard]] const std::optional<CardInfo>& card() const noexcept { return m_card; }
  [[nodiscard]] KeyState keyState() const noexcept { return m_keyState; }
  [[nodiscard]] bool ultimatelyTrusted() const noexcept { return m_trusted; }
  // Imports the card's public key from the card URL, then gpg's keyservers (network sources are
  // skipped when offline).
  void importPublicKey(bool offline);
  void importPublicKeyFromFile(const std::filesystem::path& file);
  void trustKey();
  [[nodiscard]] bool gpgBusy() const noexcept { return m_gpgBusy; }
  [[nodiscard]] const std::string& gpgStatus() const noexcept { return m_gpgStatus; }
  [[nodiscard]] bool gpgStatusIsError() const noexcept { return m_gpgStatusError; }

private:
  using ResultHandler = std::function<void(const process::RunResult&)>;

  // Runs args on a worker; `done` runs on the main loop unless this manager is gone.
  bool
  run(std::vector<std::string> args, ResultHandler done, std::optional<std::string> stdinData = std::nullopt,
      std::shared_ptr<std::atomic<bool>> cancel = nullptr, std::optional<int> timeoutSeconds = std::nullopt);
  void loadConnectedKeys();
  void loadCredentials();
  bool writeCredentials(const std::vector<std::string>& creds);
  void loadCard();
  void loadKeyState();
  void createStubs(std::string successMessage);
  void importFromKeyserver();
  void setFidoStatus(std::string message, bool error);
  void setGpgStatus(std::string message, bool error);
  void notifyChanged();

  std::shared_ptr<void> m_alive = std::make_shared<int>(0);
  ChangedCallback m_onChanged;
  std::string m_user;

  bool m_loaded = false;
  std::vector<std::string> m_connectedKeys;
  std::vector<Credential> m_credentials;
  bool m_registering = false;
  std::optional<bool> m_registerResult;
  std::shared_ptr<std::atomic<bool>> m_registerCancel;
  bool m_testing = false;
  std::unique_ptr<SecurityKeyAuthenticator> m_tester;
  std::string m_fidoStatus;
  bool m_fidoStatusError = false;

  std::optional<CardInfo> m_card;
  std::string m_primaryFingerprint;
  KeyState m_keyState = KeyState::Unknown;
  bool m_trusted = false;
  bool m_gpgBusy = false;
  std::string m_gpgStatus;
  bool m_gpgStatusError = false;
};
