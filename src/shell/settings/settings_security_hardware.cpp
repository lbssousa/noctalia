#include "shell/settings/settings_security_hardware.h"

#include "i18n/i18n.h"
#include "security/fingerprint_manager.h"
#include "security/security_key_manager.h"
#include "ui/builders.h"
#include "ui/controls/button.h"
#include "ui/controls/flex.h"
#include "ui/controls/glyph.h"
#include "ui/controls/input.h"
#include "ui/controls/label.h"
#include "ui/controls/progress_bar.h"
#include "ui/controls/select.h"
#include "ui/palette.h"
#include "ui/style.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace settings {

  namespace {

    std::unique_ptr<Label> bodyLabel(std::string text, float scale, ColorRole role = ColorRole::OnSurface) {
      return ui::label({
          .text = std::move(text),
          .fontSize = Style::fontSizeBody * scale,
          .color = colorSpecFromRole(role),
          .maxLines = 0,
      });
    }

    std::unique_ptr<Label> captionLabel(std::string text, float scale) {
      return ui::label({
          .text = std::move(text),
          .fontSize = Style::fontSizeCaption * scale,
          .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
          .maxLines = 0,
      });
    }

    std::unique_ptr<Label> sectionLabel(std::string text, float scale) {
      return ui::label({
          .text = std::move(text),
          .fontSize = Style::fontSizeCaption * scale,
          .fontWeight = FontWeight::Bold,
          .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
      });
    }

    void addStatus(Flex& parent, const std::string& message, bool error, float scale) {
      if (message.empty()) {
        return;
      }
      auto row = ui::row({.align = FlexAlign::Center, .gap = Style::spaceSm * scale});
      row->addChild(
          ui::glyph({
              .glyph = error ? "alert-circle" : "circle-check",
              .glyphSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(error ? ColorRole::Error : ColorRole::Primary),
          })
      );
      row->addChild(bodyLabel(message, scale, error ? ColorRole::Error : ColorRole::OnSurface));
      parent.addChild(std::move(row));
    }

    // "Label: value" line.
    void addInfoRow(Flex& parent, const std::string& label, const std::string& value, float scale) {
      auto row = ui::row({.align = FlexAlign::Center, .gap = Style::spaceSm * scale});
      row->addChild(
          ui::label({
              .text = label,
              .fontSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
          })
      );
      row->addChild(
          ui::label({
              .text = value,
              .fontSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurface),
              .maxLines = 0,
              .flexGrow = 1.0F,
          })
      );
      parent.addChild(std::move(row));
    }

    std::unique_ptr<Button> actionButton(
        std::string text, std::string glyph, bool enabled, ButtonVariant variant, float scale,
        std::function<void()> onClick
    ) {
      return ui::button({
          .text = std::move(text),
          .glyph = glyph.empty() ? std::nullopt : std::optional<std::string>{std::move(glyph)},
          .fontSize = Style::fontSizeBody * scale,
          .glyphSize = Style::fontSizeBody * scale,
          .enabled = enabled,
          .variant = variant,
          .minHeight = Style::controlHeight * scale,
          .paddingV = Style::spaceSm * scale,
          .paddingH = Style::spaceMd * scale,
          .gap = Style::spaceXs * scale,
          .radius = Style::scaledRadiusMd(scale),
          .onClick = std::move(onClick),
      });
    }

    std::unique_ptr<Button>
    iconButton(std::string glyph, std::string tooltip, bool enabled, float scale, std::function<void()> onClick) {
      return ui::button({
          .glyph = std::move(glyph),
          .glyphSize = Style::fontSizeBody * scale,
          .enabled = enabled,
          .variant = ButtonVariant::Ghost,
          .tooltip = std::move(tooltip),
          .minWidth = Style::controlHeightSm * scale,
          .minHeight = Style::controlHeightSm * scale,
          .padding = Style::spaceXs * scale,
          .radius = Style::scaledRadiusMd(scale),
          .onClick = std::move(onClick),
      });
    }

    std::unique_ptr<Flex> buttonRow(float scale) {
      return ui::row({.align = FlexAlign::Center, .wrap = true, .gap = Style::spaceSm * scale});
    }

    // One row of a list: leading glyph, text, then trailing controls.
    std::unique_ptr<Flex> listRow(const std::string& glyph, std::string text, float scale) {
      auto row = ui::row({
          .align = FlexAlign::Center,
          .gap = Style::spaceSm * scale,
          .paddingH = Style::spaceSm * scale,
          .fill = colorSpecFromRole(ColorRole::SurfaceVariant, 0.35F),
          .radius = Style::scaledRadiusMd(scale),
          .minHeight = Style::controlHeight * scale,
          .fillWidth = true,
      });
      row->addChild(
          ui::glyph({
              .glyph = glyph,
              .glyphSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
          })
      );
      row->addChild(
          ui::label({
              .text = std::move(text),
              .fontSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurface),
              .ellipsize = TextEllipsize::End,
              .flexGrow = 1.0F,
          })
      );
      return row;
    }

    // Trailing delete control with an inline confirmation step.
    void addDeleteControls(
        Flex& row, bool pending, bool enabled, float scale, std::function<void()> ask, std::function<void()> confirm,
        std::function<void()> dismiss
    ) {
      if (!pending) {
        row.addChild(
            iconButton("trash", i18n::tr("settings.security-hardware.delete"), enabled, scale, std::move(ask))
        );
        return;
      }
      row.addChild(actionButton(
          i18n::tr("settings.security-hardware.confirm-delete"), "trash", enabled, ButtonVariant::Destructive, scale,
          std::move(confirm)
      ));
      row.addChild(iconButton("close", i18n::tr("settings.security-hardware.cancel"), true, scale, std::move(dismiss)));
    }

    std::string scanTypeLabel(const std::string& scanType) {
      return scanType == "swipe" ? i18n::tr("settings.fingerprint.scan-type.swipe")
                                 : i18n::tr("settings.fingerprint.scan-type.press");
    }

    bool allFingersEnrolled(const FingerprintManager& manager) {
      return std::ranges::all_of(FingerprintManager::selectableFingers(), [&](const std::string& finger) {
        return std::ranges::contains(manager.enrolledFingers(), finger);
      });
    }

  } // namespace

  void buildFingerprintBlock(
      Flex& block, FingerprintManager& manager, SecurityHardwareUiState& state, const SecurityHardwareActions& actions,
      float scale
  ) {
    if (!manager.loaded()) {
      if (!manager.loading()) {
        manager.refresh();
      }
      block.addChild(captionLabel(i18n::tr("settings.security-hardware.loading"), scale));
      return;
    }

    const auto& devices = manager.devices();
    if (devices.empty()) {
      block.addChild(bodyLabel(i18n::tr("settings.fingerprint.no-reader"), scale, ColorRole::OnSurfaceVariant));
      auto buttons = buttonRow(scale);
      buttons->addChild(actionButton(
          i18n::tr("settings.security-hardware.refresh"), "refresh", true, ButtonVariant::Default, scale,
          [&manager]() { manager.refresh(); }
      ));
      block.addChild(std::move(buttons));
      return;
    }

    const bool busy = manager.busy();

    // Reader: a plain label for one reader, a selector when there are several (like GNOME's
    // device page, but inline).
    if (devices.size() == 1) {
      addInfoRow(
          block, i18n::tr("settings.fingerprint.reader"),
          devices.front().name + " · " + scanTypeLabel(devices.front().scanType), scale
      );
    } else {
      std::vector<std::string> options;
      std::vector<std::string> paths;
      std::size_t selected = 0;
      for (std::size_t i = 0; i < devices.size(); ++i) {
        options.push_back(devices[i].name + " · " + scanTypeLabel(devices[i].scanType));
        paths.push_back(devices[i].path);
        if (devices[i].path == manager.selectedDevice()) {
          selected = i;
        }
      }
      auto row = ui::row({.align = FlexAlign::Center, .gap = Style::spaceSm * scale, .fillWidth = true});
      row->addChild(
          ui::label({
              .text = i18n::tr("settings.fingerprint.reader"),
              .fontSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
          })
      );
      row->addChild(
          ui::select({
              .options = std::move(options),
              .selectedIndex = selected,
              .fontSize = Style::fontSizeBody * scale,
              .controlHeight = Style::controlHeight * scale,
              .enabled = !busy,
              .flexGrow = 1.0F,
              .onSelectionChanged = [&manager,
                                     paths = std::move(paths)](std::size_t index, std::string_view /*label*/) {
                if (index < paths.size()) {
                  manager.selectDevice(paths[index]);
                }
              },
          })
      );
      block.addChild(std::move(row));
    }

    block.addChild(sectionLabel(i18n::tr("settings.fingerprint.enrolled"), scale));
    if (manager.enrolledFingers().empty()) {
      block.addChild(captionLabel(i18n::tr("settings.fingerprint.none-enrolled"), scale));
    }
    for (const auto& finger : manager.enrolledFingers()) {
      auto row = listRow("fingerprint", FingerprintManager::fingerLabel(finger), scale);
      if (manager.mode() == FingerprintManager::Mode::Idle && manager.matchedFinger() == finger) {
        row->addChild(
            ui::glyph({
                .glyph = "circle-check",
                .glyphSize = Style::fontSizeBody * scale,
                .color = colorSpecFromRole(ColorRole::Primary),
            })
        );
      }
      addDeleteControls(
          *row, state.pendingFingerDelete == finger, !busy, scale,
          [&state, finger, rebuild = actions.requestRebuild]() {
            state.pendingFingerDelete = finger;
            rebuild();
          },
          [&state, &manager, finger]() {
            state.pendingFingerDelete.clear();
            manager.deleteFinger(finger);
          },
          [&state, rebuild = actions.requestRebuild]() {
            state.pendingFingerDelete.clear();
            rebuild();
          }
      );
      block.addChild(std::move(row));
    }

    if (manager.mode() != FingerprintManager::Mode::Enrolling) {
      addStatus(block, manager.status(), manager.statusIsError(), scale);
    }

    auto buttons = buttonRow(scale);
    buttons->addChild(actionButton(
        i18n::tr("settings.fingerprint.add"), "add", !busy && !allFingersEnrolled(manager), ButtonVariant::Primary,
        scale, actions.openFingerprintEnrollSheet
    ));
    if (manager.mode() == FingerprintManager::Mode::Verifying) {
      buttons->addChild(actionButton(
          i18n::tr("settings.fingerprint.stop-test"), "close", true, ButtonVariant::Default, scale,
          [&manager]() { manager.cancel(); }
      ));
    } else {
      buttons->addChild(actionButton(
          i18n::tr("settings.fingerprint.test"), "fingerprint", !busy && !manager.enrolledFingers().empty(),
          ButtonVariant::Default, scale, [&manager]() { manager.startVerify(); }
      ));
    }
    buttons->addChild(iconButton("refresh", i18n::tr("settings.security-hardware.refresh"), !busy, scale, [&manager]() {
      manager.refresh();
    }));
    block.addChild(std::move(buttons));
  }

  void buildFingerprintEnrollSheet(
      Flex& body, FingerprintManager& manager, const std::function<void()>& close, float scale
  ) {
    auto content = ui::column({.align = FlexAlign::Stretch, .gap = Style::spaceMd * scale, .fillWidth = true});

    const bool enrolling = manager.mode() == FingerprintManager::Mode::Enrolling;
    const bool finished = !enrolling && !manager.enrollFinger().empty();

    if (!enrolling && !finished) {
      // Step 1: pick a finger, right hand first, like GNOME Settings.
      content->addChild(bodyLabel(i18n::tr("settings.fingerprint.choose-finger"), scale));
      const auto& fingers = FingerprintManager::selectableFingers();
      const auto addHand = [&](const std::string& title, std::size_t first) {
        content->addChild(sectionLabel(title, scale));
        auto row = buttonRow(scale);
        for (std::size_t i = first; i < first + 3 && i < fingers.size(); ++i) {
          const std::string& finger = fingers[i];
          const bool enrolled = std::ranges::contains(manager.enrolledFingers(), finger);
          row->addChild(actionButton(
              FingerprintManager::fingerLabel(finger), enrolled ? "check" : "fingerprint", !enrolled,
              ButtonVariant::Outline, scale, [&manager, finger]() { manager.startEnroll(finger); }
          ));
        }
        content->addChild(std::move(row));
      };
      addHand(i18n::tr("settings.fingerprint.right-hand"), 0);
      addHand(i18n::tr("settings.fingerprint.left-hand"), 3);
      auto buttons = buttonRow(scale);
      buttons->addChild(
          actionButton(i18n::tr("settings.security-hardware.cancel"), {}, true, ButtonVariant::Default, scale, close)
      );
      content->addChild(std::move(buttons));
      body.addChild(std::move(content));
      return;
    }

    // Step 2: enrollment progress.
    content->addChild(
        ui::label({
            .text = FingerprintManager::fingerLabel(manager.enrollFinger()),
            .fontSize = Style::fontSizeTitle * scale,
            .fontWeight = FontWeight::Bold,
            .color = colorSpecFromRole(ColorRole::OnSurface),
        })
    );

    const int total = manager.enrollStagesTotal();
    const int done = manager.enrollStagesDone();
    float progress = 0.0F;
    if (manager.enrollCompleted()) {
      progress = 1.0F;
    } else if (total > 0) {
      progress = std::clamp(static_cast<float>(done) / static_cast<float>(total), 0.0F, 1.0F);
    }
    content->addChild(
        ui::progressBar({
            .progress = progress,
            .height = Style::spaceSm * scale,
            .flexGrow = 0.0F,
        })
    );
    if (total > 0) {
      content->addChild(captionLabel(
          i18n::tr(
              "settings.fingerprint.stages", "done", std::to_string(std::min(done, total)), "total",
              std::to_string(total)
          ),
          scale
      ));
    }
    addStatus(*content, manager.status(), manager.statusIsError(), scale);

    auto buttons = buttonRow(scale);
    if (enrolling) {
      buttons->addChild(
          actionButton(i18n::tr("settings.security-hardware.cancel"), {}, true, ButtonVariant::Default, scale, close)
      );
    } else {
      if (!manager.enrollCompleted()) {
        buttons->addChild(actionButton(
            i18n::tr("settings.fingerprint.try-again"), "refresh", true, ButtonVariant::Default, scale,
            [&manager, finger = manager.enrollFinger()]() { manager.startEnroll(finger); }
        ));
      }
      buttons->addChild(
          actionButton(i18n::tr("settings.security-hardware.done"), {}, true, ButtonVariant::Primary, scale, close)
      );
    }
    content->addChild(std::move(buttons));
    body.addChild(std::move(content));
  }

  void buildFido2Block(
      Flex& block, SecurityKeyManager& manager, SecurityHardwareUiState& state, const SecurityHardwareActions& actions,
      float scale
  ) {
    if (!manager.loaded()) {
      manager.refresh();
    }
    const bool busy = manager.registering() || manager.testing();

    block.addChild(sectionLabel(i18n::tr("settings.security-keys.fido.connected"), scale));
    if (manager.connectedKeys().empty()) {
      block.addChild(captionLabel(i18n::tr("settings.security-keys.fido.none-connected"), scale));
    }
    for (const auto& key : manager.connectedKeys()) {
      block.addChild(listRow("usb", key, scale));
    }

    block.addChild(sectionLabel(i18n::tr("settings.security-keys.fido.registered"), scale));
    block.addChild(captionLabel(
        i18n::tr("settings.security-keys.fido.authfile", "path", SecurityKeyManager::authfilePath().string()), scale
    ));
    if (manager.credentials().empty()) {
      block.addChild(captionLabel(i18n::tr("settings.security-keys.fido.none-registered"), scale));
    }
    for (std::size_t i = 0; i < manager.credentials().size(); ++i) {
      std::string handle = manager.credentials()[i].keyHandle;
      if (handle.size() > 16) {
        handle = handle.substr(0, 16) + "…";
      }
      auto row = listRow(
          "key", i18n::tr("settings.security-keys.fido.credential", "index", std::to_string(i + 1), "handle", handle),
          scale
      );
      addDeleteControls(
          *row, state.pendingCredentialRemove == i, !busy, scale,
          [&state, i, rebuild = actions.requestRebuild]() {
            state.pendingCredentialRemove = i;
            rebuild();
          },
          [&state, &manager, i]() {
            state.pendingCredentialRemove.reset();
            manager.removeCredential(i);
          },
          [&state, rebuild = actions.requestRebuild]() {
            state.pendingCredentialRemove.reset();
            rebuild();
          }
      );
      block.addChild(std::move(row));
    }

    if (!manager.registering()) {
      addStatus(block, manager.fidoStatus(), manager.fidoStatusIsError(), scale);
    }

    auto buttons = buttonRow(scale);
    buttons->addChild(actionButton(
        i18n::tr("settings.security-keys.fido.register"), "add", !busy, ButtonVariant::Primary, scale,
        actions.openSecurityKeyRegisterSheet
    ));
    if (SecurityKeyManager::testServiceAvailable()) {
      if (manager.testing()) {
        buttons->addChild(actionButton(
            i18n::tr("settings.security-keys.fido.stop-test"), "close", true, ButtonVariant::Default, scale,
            [&manager]() { manager.stopTest(); }
        ));
      } else {
        buttons->addChild(actionButton(
            i18n::tr("settings.security-keys.fido.test"), "key", !busy && !manager.credentials().empty(),
            ButtonVariant::Default, scale, [&manager]() { manager.startTest(); }
        ));
      }
    }
    buttons->addChild(iconButton("refresh", i18n::tr("settings.security-hardware.refresh"), !busy, scale, [&manager]() {
      manager.refresh();
    }));
    block.addChild(std::move(buttons));
  }

  void buildFido2RegisterSheet(
      Flex& body, SecurityKeyManager& manager, std::string& pin, const std::function<void()>& close, float scale
  ) {
    auto content = ui::column({.align = FlexAlign::Stretch, .gap = Style::spaceMd * scale, .fillWidth = true});

    if (manager.registering()) {
      content->addChild(
          ui::glyph({
              .glyph = "key",
              .glyphSize = Style::fontSizeHeader * 2.0F * scale,
              .color = colorSpecFromRole(ColorRole::Primary),
          })
      );
      content->addChild(bodyLabel(i18n::tr("settings.security-keys.fido.status.touch"), scale));
      auto buttons = buttonRow(scale);
      buttons->addChild(actionButton(
          i18n::tr("settings.security-hardware.cancel"), {}, true, ButtonVariant::Default, scale,
          [&manager]() { manager.cancelRegister(); }
      ));
      content->addChild(std::move(buttons));
      body.addChild(std::move(content));
      return;
    }

    if (manager.registerResult() == true) {
      addStatus(*content, manager.fidoStatus(), false, scale);
      auto buttons = buttonRow(scale);
      buttons->addChild(
          actionButton(i18n::tr("settings.security-hardware.done"), {}, true, ButtonVariant::Primary, scale, close)
      );
      content->addChild(std::move(buttons));
      body.addChild(std::move(content));
      return;
    }

    content->addChild(bodyLabel(i18n::tr("settings.security-keys.fido.register-intro"), scale));
    content->addChild(captionLabel(i18n::tr("settings.security-keys.fido.pin-hint"), scale));
    content->addChild(
        ui::input({
            .value = pin,
            .placeholder = i18n::tr("settings.security-keys.fido.pin-placeholder"),
            .fontSize = Style::fontSizeBody * scale,
            .controlHeight = Style::controlHeight * scale,
            .passwordMode = true,
            .onChange = [&pin](const std::string& value) { pin = value; },
            .onSubmit =
                [&manager, &pin](const std::string& value) {
                  pin = value;
                  manager.startRegister(pin);
                },
        })
    );
    if (manager.registerResult() == false) {
      addStatus(*content, manager.fidoStatus(), true, scale);
    }
    auto buttons = buttonRow(scale);
    buttons->addChild(actionButton(
        i18n::tr("settings.security-keys.fido.register"), "key", true, ButtonVariant::Primary, scale,
        [&manager, &pin]() { manager.startRegister(pin); }
    ));
    buttons->addChild(
        actionButton(i18n::tr("settings.security-hardware.cancel"), {}, true, ButtonVariant::Default, scale, close)
    );
    content->addChild(std::move(buttons));
    body.addChild(std::move(content));
  }

  void
  buildGpgCardBlock(Flex& block, SecurityKeyManager& manager, const SecurityHardwareActions& actions, float scale) {
    if (!manager.loaded()) {
      manager.refresh();
    }
    const auto& card = manager.card();
    const bool busy = manager.gpgBusy();

    if (!card.has_value()) {
      block.addChild(bodyLabel(
          i18n::tr(busy ? "settings.security-hardware.loading" : "settings.security-keys.gpg.no-card"), scale,
          ColorRole::OnSurfaceVariant
      ));
      auto buttons = buttonRow(scale);
      buttons->addChild(actionButton(
          i18n::tr("settings.security-hardware.refresh"), "refresh", !busy, ButtonVariant::Default, scale,
          [&manager]() { manager.refresh(); }
      ));
      block.addChild(std::move(buttons));
      return;
    }

    std::string cardName = card->vendor.empty() ? card->reader : card->vendor;
    if (!card->serial.empty()) {
      cardName += " · " + i18n::tr("settings.security-keys.gpg.serial", "serial", card->serial);
    }
    addInfoRow(block, i18n::tr("settings.security-keys.gpg.card"), cardName, scale);
    if (!card->holder.empty()) {
      addInfoRow(block, i18n::tr("settings.security-keys.gpg.holder"), card->holder, scale);
    }
    if (!card->signatureFingerprint.empty()) {
      addInfoRow(block, i18n::tr("settings.security-keys.gpg.fingerprint"), card->signatureFingerprint, scale);
    }
    if (!card->url.empty()) {
      addInfoRow(block, i18n::tr("settings.security-keys.gpg.url"), card->url, scale);
    }

    std::string stateText;
    switch (manager.keyState()) {
    case SecurityKeyManager::KeyState::Ready:
      stateText = i18n::tr("settings.security-keys.gpg.state.ready");
      break;
    case SecurityKeyManager::KeyState::PublicOnly:
      stateText = i18n::tr("settings.security-keys.gpg.state.public-only");
      break;
    case SecurityKeyManager::KeyState::Missing:
      stateText = i18n::tr("settings.security-keys.gpg.state.missing");
      break;
    case SecurityKeyManager::KeyState::Unknown:
      stateText = i18n::tr("settings.security-keys.gpg.state.no-key");
      break;
    }
    addInfoRow(block, i18n::tr("settings.security-keys.gpg.state.label"), stateText, scale);
    const bool hasPublicKey = manager.keyState() == SecurityKeyManager::KeyState::Ready
        || manager.keyState() == SecurityKeyManager::KeyState::PublicOnly;
    if (hasPublicKey) {
      addInfoRow(
          block, i18n::tr("settings.security-keys.gpg.trust.label"),
          i18n::tr(
              manager.ultimatelyTrusted() ? "settings.security-keys.gpg.trust.ultimate"
                                          : "settings.security-keys.gpg.trust.not-ultimate"
          ),
          scale
      );
    }

    addStatus(block, manager.gpgStatus(), manager.gpgStatusIsError(), scale);

    const bool hasKeyOnCard = !card->fingerprints.empty();
    auto buttons = buttonRow(scale);
    if (manager.keyState() != SecurityKeyManager::KeyState::Ready) {
      buttons->addChild(actionButton(
          i18n::tr("settings.security-keys.gpg.import"), "download", !busy && hasKeyOnCard, ButtonVariant::Primary,
          scale, [&manager, offline = actions.offline]() { manager.importPublicKey(offline); }
      ));
    }
    buttons->addChild(actionButton(
        i18n::tr("settings.security-keys.gpg.import-file"), "file-import", !busy && hasKeyOnCard,
        ButtonVariant::Default, scale, actions.browseGpgPublicKey
    ));
    if (hasPublicKey && !manager.ultimatelyTrusted()) {
      buttons->addChild(actionButton(
          i18n::tr("settings.security-keys.gpg.trust-button"), "user-check", !busy, ButtonVariant::Default, scale,
          [&manager]() { manager.trustKey(); }
      ));
    }
    buttons->addChild(iconButton("refresh", i18n::tr("settings.security-hardware.refresh"), !busy, scale, [&manager]() {
      manager.refresh();
    }));
    block.addChild(std::move(buttons));
  }

} // namespace settings
