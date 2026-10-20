#include "prompt_client/prompt_client.h"
#include "tests/test_check.h"

#include <string>

namespace {

  using secret_prompt::AskpassMode;
  using secret_prompt::planAskpass;

  void testSecret() {
    const auto plan = planAskpass("Enter passphrase for key '/home/u/.ssh/id_ed25519': ", nullptr);
    TEST_CHECK(plan.mode == AskpassMode::Secret);
    TEST_CHECK(plan.commands.size() == 2);
    TEST_CHECK(plan.commands[0] == "SETDESC Enter passphrase for key '/home/u/.ssh/id_ed25519':");
    TEST_CHECK(plan.commands[1] == "GETPIN");
  }

  void testVisible() {
    const auto user = planAskpass("Username for 'https://github.com': ", "");
    TEST_CHECK(user.commands.front() == "OPTION noctalia-visible-input");
    TEST_CHECK(user.commands.back() == "GETPIN");

    const auto host = planAskpass(
        "The authenticity of host 'h' can't be established.\nAre you sure you want to continue connecting "
        "(yes/no/[fingerprint])? ",
        nullptr
    );
    TEST_CHECK(host.commands.front() == "OPTION noctalia-visible-input");
    TEST_CHECK(host.commands[1].find("%0AAre you sure") != std::string::npos);

    TEST_CHECK(!secret_prompt::askpassWantsVisibleInput("Password for 'https://u@github.com': "));
  }

  void testConfirmAndInfo() {
    const auto confirm = planAskpass("Allow use of key?", "confirm");
    TEST_CHECK(confirm.mode == AskpassMode::Confirm);
    TEST_CHECK(confirm.commands.back() == "CONFIRM");

    const auto info = planAskpass("Confirm user presence for key ED25519-SK SHA256:x\n", "none");
    TEST_CHECK(info.mode == AskpassMode::Info);
    TEST_CHECK(info.commands.front() == "OPTION noctalia-no-buttons");
    TEST_CHECK(info.commands.back() == "MESSAGE");
    TEST_CHECK(info.commands[1] == "SETDESC Confirm user presence for key ED25519-SK SHA256:x");
  }

} // namespace

int main() {
  testSecret();
  testVisible();
  testConfirmAndInfo();
  return 0;
}
