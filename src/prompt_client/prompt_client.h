#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace secret_prompt {

  // Connects to the shell's pinentry/askpass socket for this session. Without WAYLAND_DISPLAY
  // (gpg-agent started before the session exported it), falls back to the only socket of that
  // kind in the runtime dir. Returns -1 when the shell is not reachable.
  [[nodiscard]] int connectPromptSocket(std::string_view kind);

  enum class AskpassMode {
    Secret,  // answer goes to stdout
    Confirm, // SSH_ASKPASS_PROMPT=confirm: exit status only
    Info,    // SSH_ASKPASS_PROMPT=none: shown until ssh kills us
  };

  struct AskpassPlan {
    AskpassMode mode = AskpassMode::Secret;
    // Assuan commands, the last one being GETPIN, CONFIRM or MESSAGE.
    std::vector<std::string> commands;
  };

  // `promptEnv` is SSH_ASKPASS_PROMPT (may be null).
  [[nodiscard]] AskpassPlan planAskpass(std::string_view prompt, const char* promptEnv);
  // Prompts that ask for a name or a yes/no answer rather than a secret.
  [[nodiscard]] bool askpassWantsVisibleInput(std::string_view prompt);

} // namespace secret_prompt
