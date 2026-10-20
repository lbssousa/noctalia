#include "prompt_client/prompt_client.h"

#include "security/prompt/assuan_session.h"
#include "security/prompt/prompt_socket_path.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <glob.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace secret_prompt {

  namespace {

    int connectPath(const std::string& path) {
      sockaddr_un addr{};
      addr.sun_family = AF_UNIX;
      if (path.size() >= sizeof(addr.sun_path)) {
        return -1;
      }
      std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
      const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (fd < 0) {
        return -1;
      }
      if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
      }
      return fd;
    }

    std::string lowercase(std::string_view text) {
      std::string out(text);
      std::ranges::transform(out, out.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
      return out;
    }

  } // namespace

  int connectPromptSocket(std::string_view kind) {
    if (const std::string display = waylandDisplayName(); !display.empty()) {
      return connectPath(promptSocketPath(kind, display));
    }
    const std::string pattern = promptSocketPath(kind, "*");
    glob_t matches{};
    int fd = -1;
    if (::glob(pattern.c_str(), 0, nullptr, &matches) == 0 && matches.gl_pathc == 1) {
      fd = connectPath(matches.gl_pathv[0]);
    }
    ::globfree(&matches);
    return fd;
  }

  bool askpassWantsVisibleInput(std::string_view prompt) {
    const std::string lower = lowercase(prompt);
    return lower.starts_with("username") || lower.contains("user name") || lower.contains("(yes/no");
  }

  AskpassPlan planAskpass(std::string_view prompt, const char* promptEnv) {
    AskpassPlan plan;
    const std::string_view mode = promptEnv != nullptr ? promptEnv : "";
    if (mode == "confirm") {
      plan.mode = AskpassMode::Confirm;
    } else if (mode == "none") {
      plan.mode = AskpassMode::Info;
    }

    if (plan.mode == AskpassMode::Secret && askpassWantsVisibleInput(prompt)) {
      plan.commands.emplace_back("OPTION noctalia-visible-input");
    }
    if (plan.mode == AskpassMode::Info) {
      plan.commands.emplace_back("OPTION noctalia-no-buttons");
    }
    // ssh prompts end with ": " or a newline; the panel has its own spacing.
    std::string_view text = prompt;
    while (!text.empty() && (text.back() == ' ' || text.back() == '\n')) {
      text.remove_suffix(1);
    }
    plan.commands.push_back("SETDESC " + percentEncode(text));
    switch (plan.mode) {
    case AskpassMode::Secret:
      plan.commands.emplace_back("GETPIN");
      break;
    case AskpassMode::Confirm:
      plan.commands.emplace_back("CONFIRM");
      break;
    case AskpassMode::Info:
      plan.commands.emplace_back("MESSAGE");
      break;
    }
    return plan;
  }

} // namespace secret_prompt
