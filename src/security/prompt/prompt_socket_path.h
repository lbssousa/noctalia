#pragma once

#include <cstdlib>
#include <string>
#include <string_view>
#include <unistd.h>

// Header-only so the small noctalia-pinentry / noctalia-askpass clients share it with the shell
// without linking the shell's core library.
namespace secret_prompt {

  inline std::string runtimeDir() {
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    if (runtime != nullptr && runtime[0] != '\0') {
      return runtime;
    }
    return "/run/user/" + std::to_string(::getuid());
  }

  inline std::string waylandDisplayName() {
    const char* display = std::getenv("WAYLAND_DISPLAY");
    if (display == nullptr || display[0] == '\0') {
      return {};
    }
    return display;
  }

  // "$XDG_RUNTIME_DIR/noctalia-<kind>-<display>.sock", next to the IPC socket.
  inline std::string promptSocketPath(std::string_view kind, std::string_view display) {
    return runtimeDir() + "/noctalia-" + std::string(kind) + "-" + std::string(display) + ".sock";
  }

  inline constexpr std::string_view kPinentrySocketKind = "pinentry";
  inline constexpr std::string_view kAskpassSocketKind = "askpass";

} // namespace secret_prompt
