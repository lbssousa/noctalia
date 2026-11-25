#pragma once

namespace polkit_panel {

  // What the shell does with the polkit panel after the agent's state changed.
  enum class Action {
    None,          // leave the panel as it is (or keep it closed)
    ScheduleClose, // no request left: close after a short grace period
    Open,          // open a fresh panel (replacing one that is still closing)
    Refresh,       // the open panel shows the current request
  };

  // A panel playing its close animation still counts as open for PanelManager,
  // but it is on its way out: refreshing it would make it adopt a newer request,
  // which its onClose() then cancels. It is treated as closed here, so a newer
  // request opens a fresh panel instead.
  [[nodiscard]] constexpr Action
  decideAction(bool hasPendingRequest, bool hasContent, bool panelOpen, bool panelClosing) noexcept {
    const bool usable = panelOpen && !panelClosing;
    if (!hasPendingRequest) {
      return usable ? Action::ScheduleClose : Action::None;
    }
    if (usable) {
      return Action::Refresh;
    }
    // BeginAuthentication alone has no prompt yet; show-info and request both do.
    return hasContent ? Action::Open : Action::None;
  }

} // namespace polkit_panel
