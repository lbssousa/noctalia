#pragma once

#include "security/prompt/assuan_session.h"
#include "shell/panel/panel.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

class Button;
class ConfigService;
class Flex;
class Glyph;
class Input;
class InputArea;
class Label;
class Node;
class Renderer;
class SecretPromptService;

// The "secret-prompt" panel: GnuPG passphrases and PINs (noctalia-pinentry) and SSH/git prompts
// (noctalia-askpass), drawn like the polkit panel.
class SecretPromptPanel : public Panel {
public:
  SecretPromptPanel(ConfigService* config, std::function<SecretPromptService*()> serviceProvider);

  void create() override;
  void onOpen(std::string_view context) override;
  void onClose() override;

  [[nodiscard]] float preferredWidth() const override { return scaled(480.0F); }
  [[nodiscard]] float preferredHeight() const override;
  [[nodiscard]] PanelPlacement panelPlacement() const noexcept override;
  [[nodiscard]] LayerShellLayer layer() const override { return LayerShellLayer::Overlay; }
  [[nodiscard]] LayerShellKeyboard keyboardMode() const override { return LayerShellKeyboard::Exclusive; }
  [[nodiscard]] bool dismissOnOutsideClick() const override { return false; }
  [[nodiscard]] InputArea* initialFocusArea() const override;
  [[nodiscard]] bool handleGlobalKey(std::uint32_t sym, std::uint32_t modifiers, bool pressed, bool preedit) override;

private:
  void onPanelCardOpacityChanged(float opacity) override;
  void doLayout(Renderer& renderer, float width, float height) override;
  void doUpdate(Renderer& renderer) override;
  void accept();
  void reject();
  void cancelPrompt();
  void submitSecret();
  bool handleInputKeyEvent(Input* input, std::uint32_t sym, std::uint32_t modifiers);
  void clearInputs();
  [[nodiscard]] SecretPromptService* service() const;

  ConfigService* m_config = nullptr;
  std::function<SecretPromptService*()> m_serviceProvider;
  Flex* m_rootLayout = nullptr;
  InputArea* m_focusArea = nullptr;
  Node* m_iconContainer = nullptr;
  Glyph* m_icon = nullptr;
  Label* m_titleLabel = nullptr;
  Label* m_messageLabel = nullptr;
  Label* m_promptLabel = nullptr;
  Input* m_input = nullptr;
  Input* m_repeatInput = nullptr;
  Label* m_errorLabel = nullptr;
  Flex* m_buttonRow = nullptr;
  Button* m_cancelButton = nullptr;
  Button* m_notOkButton = nullptr;
  Button* m_okButton = nullptr;
  // The request this panel shows; closing the panel cancels it.
  std::uint64_t m_trackedId = 0;
  // Local "do not match" error for SETREPEAT, cleared when the user types again.
  std::string m_localError;
  std::string m_lastLayoutKey;
  std::optional<secret_prompt::PromptKind> m_lastKind;
};
