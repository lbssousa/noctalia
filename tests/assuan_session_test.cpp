#include "security/prompt/assuan_session.h"
#include "tests/test_check.h"

#include <string>
#include <string_view>

namespace {

  using secret_prompt::AssuanSession;
  using secret_prompt::PromptKind;
  using secret_prompt::PromptOrigin;

  AssuanSession::Action feed(AssuanSession& session, std::string_view line, std::string& out) {
    out.clear();
    return session.feedLine(line, out);
  }

  void testGetPin() {
    AssuanSession session(PromptOrigin::Gpg);
    std::string out;
    TEST_CHECK(AssuanSession::greeting() == "OK Pleased to meet you\n");
    TEST_CHECK(feed(session, "OPTION ttyname=/dev/pts/1", out) == AssuanSession::Action::None && out == "OK\n");
    TEST_CHECK(feed(session, "SETDESC Please enter%0Athe passphrase%25", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "SETPROMPT Passphrase:", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "SETOK _OK", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "SETCANCEL _Cancel__x", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "SETERROR Bad passphrase", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "GETPIN", out) == AssuanSession::Action::Prompt && out.empty());
    TEST_CHECK(session.waiting());
    const auto& request = session.request();
    TEST_CHECK(request.kind == PromptKind::Pin);
    TEST_CHECK(request.description == "Please enter\nthe passphrase%");
    TEST_CHECK(request.prompt == "Passphrase:");
    TEST_CHECK(request.okLabel == "OK");
    TEST_CHECK(request.cancelLabel == "Cancel_x");
    TEST_CHECK(request.error == "Bad passphrase");
    TEST_CHECK(!request.visibleInput);

    // Lines arriving while waiting are ignored.
    TEST_CHECK(feed(session, "GETPIN", out) == AssuanSession::Action::None && out.empty());

    std::string pin = "s%e\ncret";
    out.clear();
    session.answerPin(pin, out);
    TEST_CHECK(pin.empty());
    TEST_CHECK(out == "D s%25e%0Acret\nOK\n");
    TEST_CHECK(!session.waiting());
    // The error is shown once.
    TEST_CHECK(session.request().error.empty());
    TEST_CHECK(session.request().description == "Please enter\nthe passphrase%");

    TEST_CHECK(feed(session, "BYE", out) == AssuanSession::Action::Close);
  }

  void testRepeatAndLongPin() {
    AssuanSession session(PromptOrigin::Gpg);
    std::string out;
    feed(session, "SETREPEAT Repeat:", out);
    feed(session, "SETREPEATERROR does not match", out);
    TEST_CHECK(feed(session, "GETPIN", out) == AssuanSession::Action::Prompt);
    TEST_CHECK(session.request().wantsRepeat);
    TEST_CHECK(session.request().repeatPrompt == "Repeat:");
    TEST_CHECK(session.request().repeatError == "does not match");

    std::string pin(1500, '%');
    out.clear();
    session.answerPin(pin, out);
    TEST_CHECK(out.starts_with("S PIN_REPEATED\nD "));
    TEST_CHECK(out.ends_with("\nOK\n"));
    // Every data line fits the Assuan limit and no %XX escape is split.
    std::size_t pos = out.find("D ");
    std::size_t decoded = 0;
    while (pos != std::string::npos && out.compare(pos, 2, "D ") == 0) {
      const auto end = out.find('\n', pos);
      TEST_CHECK(end - pos + 1 <= secret_prompt::kAssuanLineMax);
      const std::string_view payload(out.data() + pos + 2, end - pos - 2);
      TEST_CHECK(payload.size() % 3 == 0);
      decoded += secret_prompt::percentDecode(payload).size();
      pos = end + 1;
    }
    TEST_CHECK(decoded == 1500);
  }

  void testConfirmAndMessage() {
    AssuanSession session(PromptOrigin::Gpg);
    std::string out;
    feed(session, "SETNOTOK _No", out);
    TEST_CHECK(feed(session, "CONFIRM --one-button", out) == AssuanSession::Action::Prompt);
    TEST_CHECK(session.request().kind == PromptKind::Confirm);
    TEST_CHECK(session.request().oneButton);
    TEST_CHECK(session.request().notOkLabel == "No");
    out.clear();
    session.answerConfirm(true, out);
    TEST_CHECK(out == "OK\n");

    TEST_CHECK(feed(session, "CONFIRM", out) == AssuanSession::Action::Prompt);
    TEST_CHECK(!session.request().oneButton);
    out.clear();
    session.answerConfirm(false, out);
    TEST_CHECK(out == "ERR 83886194 Not confirmed <Pinentry>\n");

    TEST_CHECK(feed(session, "CONFIRM", out) == AssuanSession::Action::Prompt);
    out.clear();
    session.answerCancel(out);
    TEST_CHECK(out == "ERR 83886179 Operation cancelled <Pinentry>\n");

    TEST_CHECK(feed(session, "MESSAGE", out) == AssuanSession::Action::Prompt);
    TEST_CHECK(session.request().kind == PromptKind::Message);
    out.clear();
    session.answerCancel(out);
    TEST_CHECK(out == "OK\n");
  }

  void testTimeoutAndErrors() {
    AssuanSession session(PromptOrigin::Gpg);
    std::string out;
    TEST_CHECK(feed(session, "SETTIMEOUT 30", out) == AssuanSession::Action::None && out == "OK\n");
    TEST_CHECK(feed(session, "SETTIMEOUT nope", out) == AssuanSession::Action::None && out.starts_with("ERR "));
    TEST_CHECK(feed(session, "GETPIN", out) == AssuanSession::Action::Prompt);
    TEST_CHECK(session.request().timeoutSeconds == 30);
    out.clear();
    session.answerTimeout(out);
    TEST_CHECK(out == "ERR 83886142 Timeout <Pinentry>\n");

    TEST_CHECK(feed(session, "FROBNICATE", out) == AssuanSession::Action::None && out.starts_with("ERR "));
    TEST_CHECK(feed(session, "# comment", out) == AssuanSession::Action::None && out.empty());
    TEST_CHECK(feed(session, "GETINFO flavor", out) == AssuanSession::Action::None && out == "D noctalia\nOK\n");
    TEST_CHECK(feed(session, "NOP\r", out) == AssuanSession::Action::None && out == "OK\n");
    TEST_CHECK(feed(session, "SETDESC x", out) == AssuanSession::Action::None);
    TEST_CHECK(feed(session, "RESET", out) == AssuanSession::Action::None && out == "OK\n");
    TEST_CHECK(session.request().description.empty());
  }

  void testExtensionsOnlyForAskpass() {
    std::string out;
    AssuanSession gpg(PromptOrigin::Gpg);
    feed(gpg, "OPTION noctalia-visible-input", out);
    feed(gpg, "OPTION noctalia-no-buttons", out);
    TEST_CHECK(!gpg.request().visibleInput);
    TEST_CHECK(!gpg.request().noButtons);

    AssuanSession ssh(PromptOrigin::Ssh);
    feed(ssh, "OPTION noctalia-visible-input", out);
    feed(ssh, "OPTION noctalia-no-buttons", out);
    TEST_CHECK(ssh.request().visibleInput);
    TEST_CHECK(ssh.request().noButtons);
    TEST_CHECK(ssh.request().origin == PromptOrigin::Ssh);
  }

  void testHelpers() {
    TEST_CHECK(secret_prompt::percentDecode("a%2") == "a%2");
    TEST_CHECK(secret_prompt::percentDecode("%zz%41") == "%zzA");
    TEST_CHECK(secret_prompt::percentEncode("a\r\n%b") == "a%0D%0A%25b");
    TEST_CHECK(secret_prompt::stripMnemonic("_Save__As") == "Save_As");
    std::string text = "secret";
    secret_prompt::wipe(text);
    TEST_CHECK(text.empty());
  }

} // namespace

int main() {
  testGetPin();
  testRepeatAndLongPin();
  testConfirmAndMessage();
  testTimeoutAndErrors();
  testExtensionsOnlyForAskpass();
  testHelpers();
  return 0;
}
