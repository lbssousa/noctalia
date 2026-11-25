#pragma once

#include "shell/auth_text.h"
#include "shell/panel/panel.h"
#include "system/icon_resolver.h"
#include "ui/signal.h"

#include <functional>
#include <string>
#include <string_view>

class Button;
class Flex;
class Glyph;
class Image;
class Input;
class InputArea;
class Label;
class Node;
class PolkitAgent;
struct PolkitRequest;
class Renderer;
class ConfigService;

class PolkitPanel : public Panel {
public:
  PolkitPanel(ConfigService* config, std::function<PolkitAgent*()> agentProvider);

  void create() override;
  void onOpen(std::string_view context) override;
  void onClose() override;
  void onCloseStarted() override { m_closing = true; }

  float preferredWidth() const override { return scaled(480.0F); }
  // Fits its content (the prompt grows when a password is needed); this is the maximum.
  float preferredHeight() const override { return scaled(640.0F); }
  bool fitsContentHeight() const noexcept override { return true; }
  float measureContentHeight(Renderer& renderer, float contentWidth) override;
  PanelPlacement panelPlacement() const noexcept override;
  LayerShellLayer layer() const override { return LayerShellLayer::Overlay; }
  LayerShellKeyboard keyboardMode() const override { return LayerShellKeyboard::Exclusive; }
  bool dismissOnOutsideClick() const override { return false; }
  bool isModal() const noexcept override { return true; }
  InputArea* initialFocusArea() const override;
  bool handleGlobalKey(std::uint32_t sym, std::uint32_t modifiers, bool pressed, bool preedit) override;

private:
  void onPanelCardOpacityChanged(float opacity) override;
  void doLayout(Renderer& renderer, float width, float height) override;
  void doUpdate(Renderer& renderer) override;
  void submit(std::string_view response = {});
  void cancelAuth();
  void usePassword();
  bool handleInputKeyEvent(std::uint32_t sym, std::uint32_t modifiers);
  void resolveIcon(Renderer& renderer, const PolkitRequest& request);
  void loadIcon(Renderer& renderer, const std::string& path, float iconSize);
  void updateCue(auth_text::AuthCue cue, bool isError, const std::string& rawMessage);

  ConfigService* m_config = nullptr;
  Signal<>::ScopedConnection m_appIconColorizeConn;
  std::function<PolkitAgent*()> m_agentProvider;
  Flex* m_rootLayout = nullptr;
  InputArea* m_focusArea = nullptr;
  Label* m_titleLabel = nullptr;
  Label* m_messageLabel = nullptr;
  Label* m_promptLabel = nullptr;
  Label* m_supplementaryLabel = nullptr;
  Input* m_input = nullptr;
  Button* m_submitButton = nullptr;
  Button* m_cancelButton = nullptr;
  Button* m_usePasswordButton = nullptr;
  Node* m_iconContainer = nullptr;
  Image* m_icon = nullptr;
  Glyph* m_fallbackIcon = nullptr;
  Flex* m_cueBox = nullptr;
  Glyph* m_cueGlyph = nullptr;
  Label* m_cueTitle = nullptr;
  Label* m_cueDetail = nullptr;
  IconResolver m_iconResolver;
  std::string m_lastIconName;
  bool m_iconResolved = false;
  bool m_iconIsAppIcon = false;
  bool m_lastResponseRequired = false;
  bool m_lastPinPrompt = false;
  auth_text::AuthCue m_lastCue = auth_text::AuthCue::None;
  std::string m_trackedRequestCookie;
  bool m_hasTrackedRequest = false;
  // Closing: a newer request must not be adopted, or onClose() would cancel it.
  bool m_closing = false;
};
