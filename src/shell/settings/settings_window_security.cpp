#include "wayland/clipboard_service.h"
#include "config/config_types.h"
#include "core/deferred_call.h"
#include "i18n/i18n.h"
#include "security/fingerprint_manager.h"
#include "security/security_key_manager.h"
#include "shell/settings/settings_security_hardware.h"
#include "shell/settings/settings_window.h"
#include "ui/controls/flex.h"
#include "ui/controls/input.h"
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
  // Both managers report every state change; redraw the page and any open sheet.
  const auto onChanged = [this]() {
    if (isOpen()) {
      requestContentRebuild(/*refreshRegistry=*/false, /*refreshFilterRow=*/false, /*rebuildEditorSheet=*/true);
    }
  };
  if (m_fingerprints != nullptr) {
    m_fingerprints->setChangedCallback(onChanged);
  }
  if (m_securityKeys != nullptr) {
    m_securityKeys->setChangedCallback([this, onChanged]() {
      onChanged();
      // Opening or closing a sheet from inside a click handler would destroy the button being
      // clicked: do it on the next turn of the loop.
      DeferredCall::callLater([this, alive = std::weak_ptr<void>(m_securityAlive)]() {
        if (!alive.expired()) {
          syncSecurityKeyPinSheet();
        }
      });
    });
  }
}

settings::SecurityHardwareActions SettingsWindow::securityHardwareActions(const Config& cfg) {
  return settings::SecurityHardwareActions{
      .requestRebuild = [this]() { requestContentRebuild(); },
      .openFingerprintEnrollSheet = [this]() { openFingerprintEnrollSheet(); },
      .browseGpgPublicKey = [this]() { browseGpgPublicKey(); },
      .openSshCreateSheet = [this]() { openSshCreateSheet(); },
      .copyText = [this](const std::string& text) {
        return m_clipboardService != nullptr && m_clipboardService->copyText(text);
      },
      .offline = cfg.shell.offlineMode,
  };
}

void SettingsWindow::insertSecurityHardwareEntries(const Config& cfg) {
  std::vector<settings::SettingEntry> entries;
  const auto entry = [&](std::string group, std::string titleKey, std::string subtitleKey, std::string searchText,
                         std::function<void(Flex&)> build) {
    entries.push_back(
        settings::SettingEntry{
            .section = settings::SettingsSection::Security,
            .group = std::move(group),
            .title = i18n::tr(titleKey),
            .subtitle = i18n::tr(subtitleKey),
            .path = {},
            .control = settings::CustomBlockSetting{.build = std::move(build)},
            .searchText = std::move(searchText),
        }
    );
  };

  if (m_fingerprints != nullptr && m_fingerprints->serviceAvailable()) {
    entry(
        "fingerprint", "settings.fingerprint.label", "settings.fingerprint.description",
        "fingerprint reader enroll biometric fprintd digital leitor biometria",
        [this, actions = securityHardwareActions(cfg)](Flex& block) {
          if (m_fingerprints != nullptr) {
            settings::buildFingerprintBlock(block, *m_fingerprints, m_securityHardwareState, actions, uiScale());
          }
        }
    );
  }

  if (m_securityKeys != nullptr && SecurityKeyManager::fido2ToolsAvailable()) {
    entry(
        "security-keys", "settings.security-keys.fido.label", "settings.security-keys.fido.description",
        "security key yubikey fido2 u2f pam_u2f register token sudo polkit chave login",
        [this, actions = securityHardwareActions(cfg)](Flex& block) {
          if (m_securityKeys != nullptr) {
            settings::buildFido2Block(block, *m_securityKeys, m_securityHardwareState, actions, uiScale());
          }
        }
    );
  }

  if (m_securityKeys != nullptr && SecurityKeyManager::gpgAvailable()) {
    entry(
        "security-keys", "settings.security-keys.gpg.label", "settings.security-keys.gpg.description",
        "gpg gnupg openpgp smartcard card yubikey public key import stub trust cartão",
        [this, actions = securityHardwareActions(cfg)](Flex& block) {
          if (m_securityKeys != nullptr) {
            settings::buildGpgCardBlock(block, *m_securityKeys, m_securityHardwareState, actions, uiScale());
          }
        }
    );
  }

  if (m_securityKeys != nullptr && SecurityKeyManager::sshAvailable()) {
    entry(
        "security-keys", "settings.security-keys.ssh.label", "settings.security-keys.ssh.description",
        "ssh resident key yubikey fido2 sk ed25519-sk ecdsa-sk github git import ssh-keygen chave residente",
        [this, actions = securityHardwareActions(cfg)](Flex& block) {
          if (m_securityKeys != nullptr) {
            settings::buildSshBlock(block, *m_securityKeys, m_securityHardwareState, actions, uiScale());
          }
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

void SettingsWindow::syncSecurityKeyPinSheet() {
  if (m_securityKeys == nullptr || !isOpen()) {
    return;
  }
  const bool prompting = m_securityKeys->pinPrompt().has_value();
  const bool sheetOpen =
      m_securitySheet == SecuritySheet::Pin && m_editorSheetModal != nullptr && m_editorSheetModal->isOpen();
  // After the PIN went in, the sheet stays up (asking for the touch) while the operation runs; a
  // wrong PIN brings the prompt back.
  if (prompting && !sheetOpen) {
    openSecurityKeyPinSheet();
  } else if (!prompting && sheetOpen && !m_securityKeys->busy()) {
    m_closingSecuritySheet = true;
    m_editorSheetModal->close();
    m_closingSecuritySheet = false;
  }
}

void SettingsWindow::openSecurityKeyPinSheet() {
  if (m_securityKeys == nullptr || !m_securityKeys->pinPrompt().has_value()) {
    return;
  }
  if (m_editorSheetModal != nullptr && m_editorSheetModal->isOpen()) {
    m_closingSecuritySheet = true;
    m_editorSheetModal->close();
    m_closingSecuritySheet = false;
  }
  if (m_editorSheetModal == nullptr) {
    m_editorSheetModal = std::make_unique<settings::SettingsSheetModal>();
    m_editorSheetModal->initialize(m_modalHost, [this]() { dismissOpenSelectDropdown(); });
  }
  std::ranges::fill(m_securityKeyPin, '\0');
  m_securityKeyPin.clear();
  m_securitySheet = SecuritySheet::Pin;

  const auto close = [this]() {
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->close();
    }
  };
  const float scale = uiScale();
  std::string title = i18n::tr("settings.security-keys.pin-title");
  m_editorSheetModal->open(
      settings::SettingsSheetRequest{
          .sheetTitle = std::move(title),
          .populateSheetBody =
              [this, close, scale](Flex& body) {
                if (m_securityKeys != nullptr) {
                  settings::buildSecurityKeyPinSheet(
                      body, *m_securityKeys, m_securityKeyPin, &m_securityPinInput, close, scale
                  );
                }
              },
          .scale = scale,
          .minWidth = 420.0F,
          .maxWidth = 560.0F,
          .onClosed =
              [this]() {
                m_securityPinInput = nullptr;
                // Never keep the PIN around once the sheet is gone.
                std::ranges::fill(m_securityKeyPin, '\0');
                m_securityKeyPin.clear();
                m_securitySheet = SecuritySheet::None;
                if (!m_closingSecuritySheet && m_securityKeys != nullptr) {
                  // Closed by the user: drop the prompt, or stop the operation waiting for the key.
                  if (m_securityKeys->pinPrompt().has_value()) {
                    m_securityKeys->cancelPin();
                  } else if (m_securityKeys->busy()) {
                    m_securityKeys->cancel();
                  }
                }
                requestContentRebuild();
              },
          .initialFocusArea =
              [this]() -> InputArea* {
                return m_securityPinInput != nullptr ? m_securityPinInput->inputArea() : nullptr;
              },
      }
  );
}

void SettingsWindow::openSshCreateSheet() {
  if (m_securityKeys == nullptr || m_securityKeys->busy()) {
    return;
  }
  if (m_editorSheetModal != nullptr && m_editorSheetModal->isOpen()) {
    m_editorSheetModal->close();
  }
  if (m_editorSheetModal == nullptr) {
    m_editorSheetModal = std::make_unique<settings::SettingsSheetModal>();
    m_editorSheetModal->initialize(m_modalHost, [this]() { dismissOpenSelectDropdown(); });
  }
  m_sshCreateForm = settings::SshCreateForm{.options = m_securityKeys->sshDefaults(), .problem = {}};
  m_securityKeys->clearSshCreated();
  m_securitySheet = SecuritySheet::SshCreate;

  const auto close = [this]() {
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->close();
    }
  };
  const auto rebuild = [this]() {
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->rebuildBody();
    }
  };
  const auto submit = [this]() { submitSshCreateSheet(); };
  const float scale = uiScale();
  m_editorSheetModal->open(
      settings::SettingsSheetRequest{
          .sheetTitle = i18n::tr("settings.security-keys.ssh.create-title"),
          .populateSheetBody =
              [this, submit, rebuild, close, scale](Flex& body) {
                settings::buildSshCreateSheet(body, m_sshCreateForm, submit, rebuild, close, scale);
              },
          .scale = scale,
          .minWidth = 520.0F,
          .maxWidth = 680.0F,
          .onClosed =
              [this]() {
                m_securitySheet = SecuritySheet::None;
                requestContentRebuild();
              },
      }
  );
}

void SettingsWindow::submitSshCreateSheet() {
  if (m_securityKeys == nullptr) {
    return;
  }
  // The same checks the manager makes before touching the key, to say what is wrong first.
  const std::string problem = SecurityKeyManager::sshCreateProblem(m_sshCreateForm.options);
  if (!problem.empty()) {
    m_sshCreateForm.problem = "settings.security-keys.ssh.invalid." + problem;
    if (m_editorSheetModal != nullptr) {
      m_editorSheetModal->rebuildBody();
    }
    return;
  }
  auto options = m_sshCreateForm.options;
  options.replace = false;
  DeferredCall::callLater([this, options, alive = std::weak_ptr<void>(m_securityAlive)]() {
    if (alive.expired() || m_securityKeys == nullptr) {
      return;
    }
    if (m_editorSheetModal != nullptr && m_editorSheetModal->isOpen() && m_securitySheet == SecuritySheet::SshCreate) {
      m_editorSheetModal->close();
    }
    m_securityKeys->requestSshCreate(options);
  });
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
    m_securityKeys->stopWatching();
    m_securityKeys->cancelPin();
    m_securityKeys->cancel();
  }
  std::ranges::fill(m_securityKeyPin, '\0');
  m_securityKeyPin.clear();
  m_securitySheet = SecuritySheet::None;
  m_securityHardwareState = {};
}
