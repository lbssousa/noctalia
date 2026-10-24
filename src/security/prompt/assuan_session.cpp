#include "security/prompt/assuan_session.h"

#include <charconv>
#include <cstring>
#include <format>
#include <string>
#include <unistd.h>

#ifndef NOCTALIA_VERSION
#define NOCTALIA_VERSION "unknown"
#endif

namespace secret_prompt {

  namespace {

    int hexValue(char ch) {
      if (ch >= '0' && ch <= '9') {
        return ch - '0';
      }
      if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
      }
      if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
      }
      return -1;
    }

    // Splits "COMMAND args" at the first space.
    void splitCommand(std::string_view line, std::string_view& command, std::string_view& args) {
      const auto space = line.find(' ');
      if (space == std::string_view::npos) {
        command = line;
        args = {};
        return;
      }
      command = line.substr(0, space);
      args = line.substr(space + 1);
      while (!args.empty() && args.front() == ' ') {
        args.remove_prefix(1);
      }
    }

    void ok(std::string& out) { out += "OK\n"; }

    void err(std::string& out, unsigned code, std::string_view text) {
      out += std::format("ERR {} {} <Pinentry>\n", code, text);
    }

    // "D " lines, never splitting a %XX escape across lines.
    void appendData(std::string& out, std::string_view encoded) {
      constexpr std::size_t kChunk = kAssuanLineMax - 4; // "D " + payload + "\n"
      std::size_t pos = 0;
      while (pos < encoded.size()) {
        std::size_t len = std::min(kChunk, encoded.size() - pos);
        if (pos + len < encoded.size()) {
          for (std::size_t back = 1; back <= 2 && back <= len; ++back) {
            if (encoded[pos + len - back] == '%') {
              len -= back;
              break;
            }
          }
        }
        out += "D ";
        out.append(encoded.substr(pos, len));
        out += '\n';
        pos += len;
      }
    }

  } // namespace

  std::string percentDecode(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
      if (text[i] == '%' && i + 2 < text.size()) {
        const int hi = hexValue(text[i + 1]);
        const int lo = hexValue(text[i + 2]);
        if (hi >= 0 && lo >= 0) {
          out.push_back(static_cast<char>((hi << 4) | lo));
          i += 2;
          continue;
        }
      }
      out.push_back(text[i]);
    }
    return out;
  }

  std::string percentEncode(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
      const auto byte = static_cast<unsigned char>(ch);
      if (ch == '%' || byte < 0x20) {
        out += std::format("%{:02X}", byte);
      } else {
        out.push_back(ch);
      }
    }
    return out;
  }

  std::string stripMnemonic(std::string_view label) {
    std::string out;
    out.reserve(label.size());
    for (std::size_t i = 0; i < label.size(); ++i) {
      if (label[i] == '_') {
        if (i + 1 < label.size() && label[i + 1] == '_') {
          out.push_back('_');
          ++i;
        }
        continue;
      }
      out.push_back(label[i]);
    }
    return out;
  }

  void wipe(std::string& text) noexcept {
    if (!text.empty()) {
      ::explicit_bzero(text.data(), text.size());
    }
    text.clear();
  }

  AssuanSession::AssuanSession(PromptOrigin origin) : m_origin(origin) { resetRequest(); }

  AssuanSession::~AssuanSession() = default;

  std::string AssuanSession::greeting() { return "OK Pleased to meet you\n"; }

  void AssuanSession::resetRequest() {
    m_request = PromptRequest{};
    m_request.origin = m_origin;
    m_waiting = false;
  }

  void AssuanSession::beginPrompt(PromptKind kind) {
    m_request.kind = kind;
    m_waiting = true;
  }

  void AssuanSession::finishPrompt() {
    m_waiting = false;
    // pinentry shows an error once: the next GETPIN starts clean unless SETERROR comes again.
    m_request.error.clear();
    m_request.oneButton = false;
  }

  AssuanSession::Action AssuanSession::feedLine(std::string_view line, std::string& out) {
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (line.empty() || line.front() == '#') {
      return Action::None;
    }
    if (m_waiting) {
      // The client must wait for the answer; anything else is a protocol violation.
      return Action::None;
    }

    std::string_view command;
    std::string_view args;
    splitCommand(line, command, args);

    auto setField = [&](std::string& field) {
      field = percentDecode(args);
      ok(out);
      return Action::None;
    };

    if (command == "BYE") {
      out += "OK closing connection\n";
      return Action::Close;
    }
    if (command == "RESET") {
      resetRequest();
      ok(out);
      return Action::None;
    }
    if (command == "NOP"
        || command == "CLEARPASSPHRASE"
        || command == "SETQUALITYBAR"
        || command == "SETQUALITYBAR_TT"
        || command == "SETGENPIN"
        || command == "SETGENPIN_TT"
        || command == "SETREPEATOK"
        || command == "SETCONSTRAINTS") {
      ok(out);
      return Action::None;
    }
    if (command == "OPTION") {
      // Extensions only count on the askpass socket: a gpg secret is always masked.
      if (m_origin == PromptOrigin::Ssh) {
        if (args == "noctalia-visible-input") {
          m_request.visibleInput = true;
        } else if (args == "noctalia-no-buttons") {
          m_request.noButtons = true;
        }
      }
      ok(out);
      return Action::None;
    }
    if (command == "SETDESC") {
      return setField(m_request.description);
    }
    if (command == "SETPROMPT") {
      return setField(m_request.prompt);
    }
    if (command == "SETTITLE") {
      return setField(m_request.title);
    }
    if (command == "SETERROR") {
      return setField(m_request.error);
    }
    if (command == "SETOK") {
      m_request.okLabel = stripMnemonic(percentDecode(args));
      ok(out);
      return Action::None;
    }
    if (command == "SETCANCEL") {
      m_request.cancelLabel = stripMnemonic(percentDecode(args));
      ok(out);
      return Action::None;
    }
    if (command == "SETNOTOK") {
      m_request.notOkLabel = stripMnemonic(percentDecode(args));
      ok(out);
      return Action::None;
    }
    if (command == "SETKEYINFO") {
      return setField(m_request.keyInfo);
    }
    if (command == "SETREPEAT") {
      m_request.wantsRepeat = true;
      return setField(m_request.repeatPrompt);
    }
    if (command == "SETREPEATERROR") {
      return setField(m_request.repeatError);
    }
    if (command == "SETTIMEOUT") {
      int seconds = 0;
      const auto [ptr, ec] = std::from_chars(args.data(), args.data() + args.size(), seconds);
      if (ec != std::errc{} || seconds < 0) {
        err(out, kErrSyntax, "Invalid value");
        return Action::None;
      }
      m_request.timeoutSeconds = seconds;
      ok(out);
      return Action::None;
    }
    if (command == "GETINFO") {
      if (args == "flavor") {
        appendData(out, "noctalia");
      } else if (args == "version") {
        appendData(out, NOCTALIA_VERSION);
      } else if (args == "pid") {
        appendData(out, std::to_string(::getpid()));
      } else {
        err(out, kErrSyntax, "Unknown info");
        return Action::None;
      }
      ok(out);
      return Action::None;
    }
    if (command == "GETPIN") {
      beginPrompt(PromptKind::Pin);
      return Action::Prompt;
    }
    if (command == "CONFIRM") {
      m_request.oneButton = args == "--one-button";
      beginPrompt(PromptKind::Confirm);
      return Action::Prompt;
    }
    if (command == "MESSAGE") {
      beginPrompt(PromptKind::Message);
      return Action::Prompt;
    }

    err(out, kErrUnknownCommand, "Unknown command");
    return Action::None;
  }

  void AssuanSession::answerPin(std::string& pin, std::string& out) {
    if (!m_waiting || m_request.kind != PromptKind::Pin) {
      wipe(pin);
      return;
    }
    if (m_request.wantsRepeat) {
      out += "S PIN_REPEATED\n";
    }
    std::string encoded = percentEncode(pin);
    appendData(out, encoded);
    wipe(encoded);
    wipe(pin);
    ok(out);
    finishPrompt();
  }

  void AssuanSession::answerConfirm(bool confirmed, std::string& out) {
    if (!m_waiting) {
      return;
    }
    if (m_request.kind == PromptKind::Message || confirmed) {
      ok(out);
    } else {
      err(out, kErrNotConfirmed, "Not confirmed");
    }
    finishPrompt();
  }

  void AssuanSession::answerCancel(std::string& out) {
    if (!m_waiting) {
      return;
    }
    if (m_request.kind == PromptKind::Message) {
      ok(out);
    } else {
      err(out, kErrCanceled, "Operation cancelled");
    }
    finishPrompt();
  }

  void AssuanSession::answerTimeout(std::string& out) {
    if (!m_waiting) {
      return;
    }
    err(out, kErrTimeout, "Timeout");
    finishPrompt();
  }

} // namespace secret_prompt
