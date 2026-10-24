#include "shell/secret_prompt/secret_prompt_panel.h"

#include "config/config_service.h"
#include "config/config_types.h"
#include "core/input/key_modifiers.h"
#include "core/input/keybind_matcher.h"
#include "i18n/i18n.h"
#include "render/core/renderer.h"
#include "render/scene/input_area.h"
#include "security/prompt/secret_prompt_service.h"
#include "shell/auth_text.h"
#include "shell/panel/panel_manager.h"
#include "ui/builders.h"
#include "ui/controls/glyph.h"
#include "ui/palette.h"
#include "ui/style.h"

#include <algorithm>
#include <cmath>
#include <format>
#include <memory>
#include <string>

namespace {

  using auth_text::wrapLongRuns;
  using auth_text::wrappedLineCount;
  using secret_prompt::PromptKind;
  using secret_prompt::PromptOrigin;
  using secret_prompt::PromptRequest;

  constexpr int kMessageMaxLines = 8;
  constexpr int kPromptMaxLines = 3;
  constexpr int kErrorMaxLines = 4;

  std::string titleFor(const PromptRequest& request) {
    if (!request.title.empty()) {
      return request.title;
    }
    return request.origin == PromptOrigin::Gpg ? i18n::tr("auth.secret-prompt.gpg-title")
                                               : i18n::tr("auth.secret-prompt.ssh-title");
  }

  std::string_view glyphFor(const PromptRequest& request) {
    return request.origin == PromptOrigin::Gpg ? "key" : "terminal-2";
  }

  bool needsInput(const PromptRequest& request) { return request.kind == PromptKind::Pin; }

  bool showsCancel(const PromptRequest& request) {
    return request.kind != PromptKind::Message && !request.oneButton && !request.noButtons;
  }

  bool showsNotOk(const PromptRequest& request) {
    return request.kind == PromptKind::Confirm && !request.notOkLabel.empty() && !request.noButtons;
  }

  std::string okLabelFor(const PromptRequest& request) {
    if (!request.okLabel.empty()) {
      return request.okLabel;
    }
    return request.kind == PromptKind::Pin ? i18n::tr("auth.secret-prompt.unlock") : i18n::tr("auth.secret-prompt.ok");
  }

  std::string placeholderFor(const PromptRequest& request) {
    return request.visibleInput ? i18n::tr("auth.secret-prompt.answer-placeholder")
                                : i18n::tr("auth.secret-prompt.passphrase-placeholder");
  }

  std::string repeatPlaceholderFor(const PromptRequest& request) {
    std::string text = request.repeatPrompt;
    while (!text.empty() && (text.back() == ':' || text.back() == ' ')) {
      text.pop_back();
    }
    return text.empty() ? i18n::tr("auth.secret-prompt.repeat-placeholder") : text;
  }

} // namespace

SecretPromptPanel::SecretPromptPanel(ConfigService* config, std::function<SecretPromptService*()> serviceProvider)
    : m_config(config), m_serviceProvider(std::move(serviceProvider)) {}

SecretPromptService* SecretPromptPanel::service() const {
  return m_serviceProvider != nullptr ? m_serviceProvider() : nullptr;
}

PanelPlacement SecretPromptPanel::panelPlacement() const noexcept {
  // Shares the polkit panel's placement: both are the shell's authentication dialog.
  return m_config != nullptr ? m_config->config().shell.panel.polkitPlacement : PanelPlacement::Floating;
}

float SecretPromptPanel::preferredHeight() const {
  const float scale = contentScale();
  const float bodyLine = Style::fontSizeBody * scale * 1.35F;
  const float titleLine = Style::fontSizeTitle * scale * 1.35F;
  const float captionLine = Style::fontSizeCaption * scale * 1.35F;
  const float iconSize = scaled(48.0F);
  const float pad = Style::spaceLg * scale;
  const float gapMd = Style::spaceMd * scale;
  const float gapSm = Style::spaceSm * scale;
  const float control = Style::controlHeight * scale;

  const float contentW = preferredWidth() - scaled(Style::panelPadding) * 2.0F;
  const float innerW = std::max(1.0F, contentW - pad * 2.0F);
  const float messageW = std::max(1.0F, innerW - iconSize - gapMd);
  const float avgChar = Style::fontSizeBody * scale * 0.55F;
  const int messageChars = std::max(1, static_cast<int>(messageW / avgChar));
  const int innerChars = std::max(1, static_cast<int>(innerW / avgChar));

  PromptRequest request;
  if (SecretPromptService* svc = service(); svc != nullptr && svc->hasPendingRequest()) {
    request = svc->pendingRequest();
  }
  const int messageLines =
      std::max(1, wrappedLineCount(wrapLongRuns(request.description), messageChars, kMessageMaxLines));
  const int promptLines = wrappedLineCount(wrapLongRuns(request.prompt), innerChars, kPromptMaxLines);
  const std::string& error = m_localError.empty() ? request.error : m_localError;
  const int errorLines = wrappedLineCount(wrapLongRuns(error), innerChars, kErrorMaxLines);

  const float top = std::max(iconSize, titleLine + static_cast<float>(messageLines) * bodyLine);
  float bottom = 0.0F;
  if (promptLines > 0) {
    bottom += static_cast<float>(promptLines) * bodyLine + gapSm;
  }
  if (needsInput(request)) {
    bottom += control + gapSm;
    if (request.wantsRepeat) {
      bottom += control + gapSm;
    }
  }
  if (errorLines > 0) {
    bottom += static_cast<float>(errorLines) * captionLine + gapSm;
  }
  if (!request.noButtons) {
    bottom += control;
  }

  return std::ceil(pad * 2.0F + top + gapMd + bottom + scaled(Style::panelPadding) * 2.0F + gapSm);
}

void SecretPromptPanel::create() {
  const float scale = contentScale();
  const float iconSize = scaled(48.0F);
  auto root = ui::column({
      .out = &m_rootLayout,
      .align = FlexAlign::Stretch,
      .gap = Style::spaceMd * scale,
      .padding = Style::spaceLg * scale,
  });

  auto focusArea = ui::inputArea({});
  focusArea->setFocusable(true);
  focusArea->setVisible(false);
  m_focusArea = static_cast<InputArea*>(root->addChild(std::move(focusArea)));

  auto iconContainer = ui::node({
      .out = &m_iconContainer,
      .width = iconSize,
      .height = iconSize,
  });
  iconContainer->addChild(
      ui::glyph({
          .out = &m_icon,
          .glyph = "key",
          .glyphSize = iconSize * 0.65F,
          .color = colorSpecFromRole(ColorRole::OnSurfaceVariant),
      })
  );

  root->addChild(
      ui::row(
          {.align = FlexAlign::Center, .gap = Style::spaceMd * scale}, std::move(iconContainer),
          ui::column(
              {.align = FlexAlign::Stretch, .flexGrow = 1.0F},
              ui::label({
                  .out = &m_titleLabel,
                  .fontSize = Style::fontSizeTitle * scale,
                  .fontWeight = FontWeight::Bold,
                  .color = colorSpecFromRole(ColorRole::Primary),
              }),
              ui::label({
                  .out = &m_messageLabel,
                  .fontSize = Style::fontSizeBody * scale,
                  .color = colorSpecFromRole(ColorRole::OnSurface),
                  .maxLines = kMessageMaxLines,
              })
          )
      )
  );

  auto onEdit = [this](const std::string& /*value*/) {
    if (!m_localError.empty()) {
      m_localError.clear();
      PanelManager::instance().refresh();
    }
  };

  root->addChild(
      ui::column(
          {.align = FlexAlign::Stretch, .gap = Style::spaceSm * scale},
          ui::label({
              .out = &m_promptLabel,
              .fontSize = Style::fontSizeBody * scale,
              .color = colorSpecFromRole(ColorRole::OnSurface),
              .maxLines = kPromptMaxLines,
          }),
          ui::input({
              .out = &m_input,
              .passwordMode = true,
              .surfaceOpacity = panelCardOpacity(),
              .onChange = onEdit,
              .onSubmit = [this](const std::string& /*value*/) { accept(); },
              .onKeyEvent = [this](
                                std::uint32_t sym, std::uint32_t modifiers
                            ) { return handleInputKeyEvent(m_input, sym, modifiers); },
          }),
          ui::input({
              .out = &m_repeatInput,
              .passwordMode = true,
              .surfaceOpacity = panelCardOpacity(),
              .visible = false,
              .onChange = onEdit,
              .onSubmit = [this](const std::string& /*value*/) { accept(); },
              .onKeyEvent = [this](
                                std::uint32_t sym, std::uint32_t modifiers
                            ) { return handleInputKeyEvent(m_repeatInput, sym, modifiers); },
          }),
          ui::label({
              .out = &m_errorLabel,
              .fontSize = Style::fontSizeCaption * scale,
              .color = colorSpecFromRole(ColorRole::Error),
              .maxLines = kErrorMaxLines,
          }),
          ui::row(
              {
                  .out = &m_buttonRow,
                  .align = FlexAlign::Center,
                  .justify = FlexJustify::End,
                  .wrap = true,
                  .gap = Style::spaceSm * scale,
                  .fillWidth = true,
              },
              ui::button({
                  .out = &m_cancelButton,
                  .text = i18n::tr("common.actions.cancel"),
                  .variant = ButtonVariant::Outline,
                  .onClick =
                      [this]() {
                        cancelPrompt();
                        PanelManager::instance().close();
                      },
              }),
              ui::button({
                  .out = &m_notOkButton,
                  .variant = ButtonVariant::Outline,
                  .onClick = [this]() { reject(); },
              }),
              ui::button({
                  .out = &m_okButton,
                  .variant = ButtonVariant::Primary,
                  .onClick = [this]() { accept(); },
              })
          )
      )
  );
  setRoot(std::move(root));
}

void SecretPromptPanel::onOpen(std::string_view /*context*/) {
  m_trackedId = 0;
  m_localError.clear();
  m_lastLayoutKey.clear();
  m_lastKind.reset();
  if (SecretPromptService* svc = service(); svc != nullptr && svc->hasPendingRequest()) {
    m_trackedId = svc->pendingId();
  }
  clearInputs();
}

void SecretPromptPanel::onClose() {
  // Closing the panel settles the request it showed; a newer one in the queue survives.
  if (SecretPromptService* svc = service();
      svc != nullptr && m_trackedId != 0 && svc->hasPendingRequest() && svc->pendingId() == m_trackedId) {
    svc->cancel();
  }
  clearInputs();
  m_trackedId = 0;
  m_localError.clear();
  m_lastLayoutKey.clear();
  m_lastKind.reset();
  clearReleasedRoot();

  m_rootLayout = nullptr;
  m_focusArea = nullptr;
  m_iconContainer = nullptr;
  m_icon = nullptr;
  m_titleLabel = nullptr;
  m_messageLabel = nullptr;
  m_promptLabel = nullptr;
  m_input = nullptr;
  m_repeatInput = nullptr;
  m_errorLabel = nullptr;
  m_buttonRow = nullptr;
  m_cancelButton = nullptr;
  m_notOkButton = nullptr;
  m_okButton = nullptr;
}

void SecretPromptPanel::clearInputs() {
  if (m_input != nullptr) {
    m_input->setValue("");
  }
  if (m_repeatInput != nullptr) {
    m_repeatInput->setValue("");
  }
}

InputArea* SecretPromptPanel::initialFocusArea() const {
  SecretPromptService* svc = service();
  if (svc != nullptr && svc->hasPendingRequest() && needsInput(svc->pendingRequest()) && m_input != nullptr) {
    return m_input->inputArea();
  }
  return m_focusArea;
}

bool SecretPromptPanel::handleGlobalKey(std::uint32_t sym, std::uint32_t modifiers, bool pressed, bool /*preedit*/) {
  if (!pressed) {
    return false;
  }
  if (KeybindMatcher::matches(KeybindAction::Cancel, sym, modifiers)) {
    cancelPrompt();
    PanelManager::instance().close();
    return true;
  }
  // Confirmations and messages have no input to submit from: Enter means OK.
  if (KeybindMatcher::matches(KeybindAction::Validate, sym, modifiers)) {
    if (SecretPromptService* svc = service(); svc != nullptr
        && svc->hasPendingRequest()
        && !needsInput(svc->pendingRequest())
        && !svc->pendingRequest().noButtons) {
      accept();
      return true;
    }
  }
  return false;
}

void SecretPromptPanel::doLayout(Renderer& renderer, float width, float height) {
  if (m_rootLayout == nullptr) {
    return;
  }
  m_rootLayout->setSize(width, height);
  m_rootLayout->layout(renderer);
  if (m_iconContainer != nullptr && m_icon != nullptr) {
    const float ox = std::round((m_iconContainer->width() - m_icon->width()) * 0.5F);
    const float oy = std::round((m_iconContainer->height() - m_icon->height()) * 0.5F);
    m_icon->setPosition(ox, oy);
  }
}

void SecretPromptPanel::doUpdate(Renderer& /*renderer*/) {
  SecretPromptService* svc = service();
  if (svc == nullptr
      || m_titleLabel == nullptr
      || m_messageLabel == nullptr
      || m_promptLabel == nullptr
      || m_input == nullptr
      || m_repeatInput == nullptr
      || m_errorLabel == nullptr
      || m_buttonRow == nullptr
      || m_cancelButton == nullptr
      || m_notOkButton == nullptr
      || m_okButton == nullptr
      || m_icon == nullptr) {
    return;
  }
  if (!svc->hasPendingRequest()) {
    return;
  }
  const PromptRequest request = svc->pendingRequest();
  const std::uint64_t id = svc->pendingId();
  const bool newRequest = id != m_trackedId;
  // gpg can follow a GETPIN with a CONFIRM on the same connection (weak passphrase warning).
  const bool kindChanged = m_lastKind.has_value() && *m_lastKind != request.kind;
  m_lastKind = request.kind;
  if (newRequest) {
    // The next queued request reuses the open panel.
    m_trackedId = id;
    m_localError.clear();
    clearInputs();
  }

  m_icon->setGlyph(glyphFor(request));
  m_titleLabel->setText(titleFor(request));
  m_messageLabel->setText(wrapLongRuns(request.description));
  m_messageLabel->setVisible(!request.description.empty());
  m_promptLabel->setText(wrapLongRuns(request.prompt));
  m_promptLabel->setVisible(!request.prompt.empty());

  const bool input = needsInput(request);
  m_input->setVisible(input);
  m_input->setPasswordMode(!request.visibleInput);
  m_input->setPlaceholder(placeholderFor(request));
  m_repeatInput->setVisible(input && request.wantsRepeat);
  m_repeatInput->setPlaceholder(repeatPlaceholderFor(request));

  const std::string& error = m_localError.empty() ? request.error : m_localError;
  m_errorLabel->setText(wrapLongRuns(error));
  m_errorLabel->setVisible(!error.empty());
  m_input->setInvalid(!request.error.empty() && m_localError.empty());
  m_repeatInput->setInvalid(!m_localError.empty());

  m_buttonRow->setVisible(!request.noButtons);
  m_cancelButton->setVisible(showsCancel(request));
  m_cancelButton->setText(request.cancelLabel.empty() ? i18n::tr("common.actions.cancel") : request.cancelLabel);
  m_notOkButton->setVisible(showsNotOk(request));
  m_notOkButton->setText(request.notOkLabel);
  m_okButton->setText(okLabelFor(request));

  const std::string layoutKey = std::format(
      "{}|{}|{}|{}|{}|{}", id, static_cast<int>(request.kind), request.wantsRepeat, request.noButtons, error,
      request.description.size()
  );
  if (layoutKey != m_lastLayoutKey) {
    m_lastLayoutKey = layoutKey;
    if (auto* manager = PanelManager::current(); manager != nullptr && manager->isOpenPanel("secret-prompt")) {
      manager->relayoutActivePanelPreferredSize();
      if (newRequest || kindChanged) {
        manager->focusArea(input ? m_input->inputArea() : m_focusArea);
      }
    }
  }
}

void SecretPromptPanel::submitSecret() {
  SecretPromptService* svc = service();
  if (svc == nullptr || m_input == nullptr || m_repeatInput == nullptr) {
    return;
  }
  const PromptRequest request = svc->pendingRequest();
  std::string secret = m_input->value();
  if (request.wantsRepeat) {
    std::string repeated = m_repeatInput->value();
    const bool match = repeated == secret;
    secret_prompt::wipe(repeated);
    if (!match) {
      secret_prompt::wipe(secret);
      m_localError = request.repeatError.empty() ? i18n::tr("auth.secret-prompt.mismatch") : request.repeatError;
      m_repeatInput->setValue("");
      PanelManager::instance().focusArea(m_repeatInput->inputArea());
      PanelManager::instance().refresh();
      return;
    }
  }
  clearInputs();
  svc->submitSecret(secret);
}

void SecretPromptPanel::accept() {
  SecretPromptService* svc = service();
  if (svc == nullptr || !svc->hasPendingRequest()) {
    return;
  }
  if (needsInput(svc->pendingRequest())) {
    submitSecret();
  } else {
    svc->confirm(true);
  }
}

void SecretPromptPanel::reject() {
  if (SecretPromptService* svc = service(); svc != nullptr && svc->hasPendingRequest()) {
    svc->confirm(false);
  }
}

void SecretPromptPanel::cancelPrompt() {
  clearInputs();
  if (SecretPromptService* svc = service(); svc != nullptr && svc->hasPendingRequest()) {
    svc->cancel();
  }
}

bool SecretPromptPanel::handleInputKeyEvent(Input* input, std::uint32_t sym, std::uint32_t modifiers) {
  if (KeybindMatcher::matches(KeybindAction::Validate, sym, modifiers)) {
    // Enter in the first field moves to the confirmation field when it is still empty.
    if (input == m_input && m_repeatInput != nullptr && m_repeatInput->visible() && m_repeatInput->value().empty()) {
      PanelManager::instance().focusArea(m_repeatInput->inputArea());
      return true;
    }
    accept();
    return true;
  }
  if (KeybindMatcher::matches(KeybindAction::TabNext, sym, modifiers)
      || KeybindMatcher::matches(KeybindAction::TabPrevious, sym, modifiers)) {
    if (m_repeatInput != nullptr && m_repeatInput->visible()) {
      PanelManager::instance().focusArea((input == m_input ? m_repeatInput : m_input)->inputArea());
      return true;
    }
    return false;
  }
  const bool shift = (modifiers & KeyMod::Shift) != 0;
  if (KeybindMatcher::matches(KeybindAction::Left, sym, modifiers)) {
    input->moveCaretLeft(shift);
    return true;
  }
  if (KeybindMatcher::matches(KeybindAction::Right, sym, modifiers)) {
    input->moveCaretRight(shift);
    return true;
  }
  return false;
}

void SecretPromptPanel::onPanelCardOpacityChanged(float opacity) {
  if (m_input != nullptr) {
    m_input->setSurfaceOpacity(opacity);
  }
  if (m_repeatInput != nullptr) {
    m_repeatInput->setSurfaceOpacity(opacity);
  }
}
