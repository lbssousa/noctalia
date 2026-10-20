#pragma once

#include <string>
#include <string_view>

namespace secret_prompt {

  // Who connected: the gpg-agent (through noctalia-pinentry) or ssh/git (through noctalia-askpass).
  // Decided by the socket the client reached, never by anything the client sends.
  enum class PromptOrigin {
    Gpg,
    Ssh,
  };

  enum class PromptKind {
    Pin,     // GETPIN: a secret (or, for askpass, a visible answer) goes back to the client
    Confirm, // CONFIRM: OK / not OK / cancel
    Message, // MESSAGE: informational, dismissed with OK
  };

  struct PromptRequest {
    PromptKind kind = PromptKind::Pin;
    PromptOrigin origin = PromptOrigin::Gpg;
    std::string title;
    std::string description;
    std::string prompt;
    std::string error;
    std::string okLabel;
    std::string cancelLabel;
    std::string notOkLabel;
    std::string keyInfo;
    // SETREPEAT: ask the secret twice; the panel checks the match before answering.
    bool wantsRepeat = false;
    std::string repeatPrompt;
    std::string repeatError;
    // CONFIRM --one-button: a single OK, no cancel.
    bool oneButton = false;
    // Extensions sent by noctalia-askpass.
    bool visibleInput = false;
    bool noButtons = false;
    int timeoutSeconds = 0;
  };

  // gpg-error codes with GPG_ERR_SOURCE_PINENTRY (5 << 24), as real pinentries report them.
  inline constexpr unsigned kErrCanceled = (5U << 24) | 99U;
  inline constexpr unsigned kErrNotConfirmed = (5U << 24) | 114U;
  inline constexpr unsigned kErrTimeout = (5U << 24) | 62U;
  inline constexpr unsigned kErrUnknownCommand = (5U << 24) | 275U;
  inline constexpr unsigned kErrSyntax = (5U << 24) | 276U;

  // Assuan line limit (including the trailing newline).
  inline constexpr std::size_t kAssuanLineMax = 1000;

  // Server half of the pinentry Assuan protocol, without any I/O: lines go in, replies are
  // appended to an output string. GETPIN/CONFIRM/MESSAGE leave the session waiting until one of
  // the answer*() calls settles it.
  class AssuanSession {
  public:
    enum class Action {
      None,   // reply (if any) is in the output, keep reading
      Prompt, // a request is waiting for the user
      Close,  // BYE or a fatal error: flush the output and close
    };

    explicit AssuanSession(PromptOrigin origin);
    ~AssuanSession();

    AssuanSession(const AssuanSession&) = delete;
    AssuanSession& operator=(const AssuanSession&) = delete;

    [[nodiscard]] static std::string greeting();

    // One line without its trailing '\n'.
    Action feedLine(std::string_view line, std::string& out);

    [[nodiscard]] bool waiting() const noexcept { return m_waiting; }
    [[nodiscard]] const PromptRequest& request() const noexcept { return m_request; }

    // Answers the waiting GETPIN. The secret is wiped from `pin` and from internal buffers.
    void answerPin(std::string& pin, std::string& out);
    // Answers the waiting CONFIRM (or dismisses MESSAGE, where `confirmed` is ignored).
    void answerConfirm(bool confirmed, std::string& out);
    void answerCancel(std::string& out);
    void answerTimeout(std::string& out);

  private:
    void resetRequest();
    void beginPrompt(PromptKind kind);
    void finishPrompt();

    PromptOrigin m_origin;
    PromptRequest m_request;
    bool m_waiting = false;
  };

  // Percent-decoding of SET* arguments ("%0A" → '\n').
  [[nodiscard]] std::string percentDecode(std::string_view text);
  // Percent-encoding for data lines and command arguments: '%', CR, LF and other controls.
  [[nodiscard]] std::string percentEncode(std::string_view text);
  // pinentry labels mark accelerators with '_' ("_OK"); "__" is a literal underscore.
  [[nodiscard]] std::string stripMnemonic(std::string_view label);
  // Overwrites the bytes of a string before it is released.
  void wipe(std::string& text) noexcept;

} // namespace secret_prompt
