#include "config/config_types.h"
#include "i18n/i18n.h"
#include "security/fingerprint_manager.h"
#include "security/security_key_manager.h"
#include "shell/settings/settings_security_hardware.h"
#include "shell/settings/settings_window.h"
#include "ui/controls/flex.h"
#include "ui/dialogs/file_dialog.h"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <utility>

void SettingsWindow::setSecurityHardware(FingerprintManager* fingerprints, SecurityKeyManager* securityKeys) {
  if (m_fingerprints != nullptr && m_fingerprints != fingerprints) {
    m_fingerprints->setChangedCallback({});
  }
  if (m_securityKeys != nullptr && m_securityKeys != securityKeys) {
    m_securityKeys->setChangedCallback({});
  }
  m_fingerprints = fingerprints;
  m_securityKeys = securityKeys;
  // Both managers report every state change; redraw the page and any open enroll/register sheet.
  const auto onChanged = [this]() {
    if (isOpen()) {
      requestContentRebuild(/*refreshRegistry=*/false, /*refreshFilterRow=*/false, /*rebuildEditorSheet=*/true);
    }
  };
  if (m_fingerprints != nullptr) {
    m_fingerprints->setChangedCallback(onChanged);
  }
  if (m_securityKeys != nullptr) {
    m_securityKeys->setChangedCallback(onChanged);
  }
}

settings::SecurityHardwareActions SettingsWindow::securityHardwareActions(const Config& cfg) {
  return settings::SecurityHardwareActions{
      .requestRebuild = [this]() { requestContentRebuild(); },
      .openFingerprintEnrollSheet = [this]() { openFingerprintEnrollSheet(); },
      .openSecurityKeyRegisterSheet = [this]() { openSecurityKeyRegisterSheet(); },
      .browseGpgPublicKey = [this]() { browseGpgPublicKey(); },
      .offline = cfg.shell.offlineMode,
  };
}

void SettingsWindow::insertSecurityHardwareEntries(const Config& cfg) {
  std::vector<settings::SettingEntry> entries;

  if (m_fingerprints != nullptr && m_fingerprints->serviceAvailable()) {
    entries.push_back(
        settings::SettingEntry{
            .section = settings::SettingsSection::Security,
            .group = "fingerprint",
            .title = i18n::tr("settings.fingerprint.label"),
            .subtitle = i18n::tr("settings.fingerprint.description"),
            .path = {},
            .control =
                settings::CustomBlockSetting{
                    .build =
                        [this, actions = securityHardwareActions(cfg)](Flex& block) {
                          if (m_fingerprints != nullptr) {
                            settings::buildFingerprintBlock(
                                block, *m_fingerprints, m_securityHardwareState, actions, uiScale()
                            );
                          }
                        },
                },
            .searchText = "fingerprint reader enroll biometric fprintd digital leitor biometria",
        }
    );
  }

  if (m_securityKeys != nullptr && SecurityKeyManager::fido2ToolsAvailable()) {
    entries.push_back(
        settings::SettingEntry{
            .section = settings::SettingsSection::Security,
            .group = "security-keys",
            .title = i18n::tr("settings.security-keys.fido.label"),
            .subtitle = i18n::tr("settings.security-keys.fido.description"),
            .path = {},
            .control =
                settings::CustomBlockSetting{
                    .build =
                        [this, actions = securityHardwareActions(cfg)](Flex& block) {
                          if (m_securityKeys != nullptr) {
                            settings::buildFido2Block(
                                block, *m_securityKeys, m_securityHardwareState, actions, uiScale()
                            );
                          }
                        },
                },
            .searchText = "security key yubikey fido2 u2f pam_u2f register token chave",
        }
    );
  }

  if (m_securityKeys != nullptr && SecurityKeyManager::gpgAvailable()) {
    entries.push_back(
        settings::SettingEntry{
            .section = settings::SettingsSection::Security,
            .group = "security-keys",
            .title = i18n::tr("settings.security-keys.gpg.label"),
            .subtitle = i18n::tr("settings.security-keys.gpg.description"),
            .path = {},
            .control =
                settings::CustomBlockSetting{
                    .build =
                        [this, actions = securityHardwareActions(cfg)](Flex& block) {
                          if (m_securityKeys != nullptr) {
                            settings::buildGpgCardBlock(block, *m_securityKeys, actions, uiScale());
                          }
                        },
                },
            .searchText = "gpg gnupg openpgp smartcard card yubikey public key import stub trust",
        }
    );
  }

  if (entries.empty()) {
    return;
  }

  // Right after the authentication group, ahead of the lock screen settings.
  auto it = std::ranges::find_if(m_settingsRegistry, [](const settings::SettingEntry& e) {
    return e.section == settings::SettingsSection::Security && e.group == "lock-screen";
  });
  if (it == m_settingsRegistry.end()) {
    const auto last = std::ranges::find_last_if(m_settingsRegistry, [](const settings::SettingEntry& e) {
      return e.section == settings::SettingsSection::Security;
    });
    it = last.empty() ? m_settingsRegistry.end() : std::next(last.begin());
  }
  m_settingsRegistry.insert(it, std::make_move_iterator(entries.begin()), std::make_move_iterator(entries.end()));
}

void SettingsWindow::openFingerprintEnrollSheet() {
  if (m_fingerprints == nullptr || m_fingerprints->busy()) {
    return;
  }
  if (m_editorSheetModal != nullptr && m_editorSheetModal->isOpen()) {
    m_editorSheetModal->close();
  }
  if (m_editorSheetModal == nullptr) {
    m_editorSheetModal = std::make_unique<settings::SettingsSheetModal>();
    m_editorSheetModal->initialize(m_modalHost, [this]() { dismissOpenSelectDropdown(); });
  }
  m_fingerprints->resetEnrollment();

  const auto close = [this]() {
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->close();
    }
  };
  const float scale = uiScale();
  m_editorSheetModal->open(
      settings::SettingsSheetRequest{
          .sheetTitle = i18n::tr("settings.fingerprint.enroll-title"),
          .populateSheetBody =
              [this, close, scale](Flex& body) {
                if (m_fingerprints != nullptr) {
                  settings::buildFingerprintEnrollSheet(body, *m_fingerprints, close, scale);
                }
              },
          .scale = scale,
          .minWidth = 480.0F,
          .maxWidth = 640.0F,
          .onClosed =
              [this]() {
                if (m_fingerprints != nullptr) {
                  if (m_fingerprints->mode() == FingerprintManager::Mode::Enrolling) {
                    m_fingerprints->cancel();
                  }
                  m_fingerprints->resetEnrollment();
                }
                requestContentRebuild();
              },
      }
  );
}

void SettingsWindow::openSecurityKeyRegisterSheet() {
  if (m_securityKeys == nullptr || m_securityKeys->registering()) {
    return;
  }
  if (m_editorSheetModal != nullptr && m_editorSheetModal->isOpen()) {
    m_editorSheetModal->close();
  }
  if (m_editorSheetModal == nullptr) {
    m_editorSheetModal = std::make_unique<settings::SettingsSheetModal>();
    m_editorSheetModal->initialize(m_modalHost, [this]() { dismissOpenSelectDropdown(); });
  }
  m_securityKeys->clearRegisterResult();
  m_securityKeyPin.clear();

  const auto close = [this]() {
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->close();
    }
  };
  const float scale = uiScale();
  m_editorSheetModal->open(
      settings::SettingsSheetRequest{
          .sheetTitle = i18n::tr("settings.security-keys.fido.register-title"),
          .populateSheetBody =
              [this, close, scale](Flex& body) {
                if (m_securityKeys != nullptr) {
                  settings::buildFido2RegisterSheet(body, *m_securityKeys, m_securityKeyPin, close, scale);
                }
              },
          .scale = scale,
          .minWidth = 480.0F,
          .maxWidth = 640.0F,
          .onClosed =
              [this]() {
                // Never keep the PIN around once the sheet is gone.
                std::ranges::fill(m_securityKeyPin, '\0');
                m_securityKeyPin.clear();
                if (m_securityKeys != nullptr) {
                  m_securityKeys->cancelRegister();
                }
                requestContentRebuild();
              },
      }
  );
}

void SettingsWindow::browseGpgPublicKey() {
  if (m_securityKeys == nullptr) {
    return;
  }
  FileDialogOptions options;
  options.mode = FileDialogMode::Open;
  options.title = i18n::tr("settings.security-keys.gpg.import-file-title");
  options.extensions = {".asc", ".gpg", ".pub", ".key"};
  (void)FileDialog::open(std::move(options), [this](std::optional<std::filesystem::path> result) {
    if (result.has_value() && m_securityKeys != nullptr) {
      m_securityKeys->importPublicKeyFromFile(*result);
    }
  });
}

void SettingsWindow::stopSecurityHardware() {
  if (m_fingerprints != nullptr) {
    m_fingerprints->cancel();
    m_fingerprints->resetEnrollment();
  }
  if (m_securityKeys != nullptr) {
    m_securityKeys->stopTest();
    m_securityKeys->cancelRegister();
  }
  m_securityHardwareState = {};
}
