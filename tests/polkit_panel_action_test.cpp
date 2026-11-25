#include "shell/polkit/polkit_panel_action.h"
#include "tests/test_check.h"

namespace {

  using polkit_panel::Action;
  using polkit_panel::decideAction;

  void testNoRequestClosesOpenPanel() {
    TEST_CHECK(decideAction(false, false, true, false) == Action::ScheduleClose);
    TEST_CHECK(decideAction(false, false, false, false) == Action::None);
    // Already closing: nothing left to do.
    TEST_CHECK(decideAction(false, false, true, true) == Action::None);
  }

  void testRequestRefreshesOpenPanel() {
    TEST_CHECK(decideAction(true, false, true, false) == Action::Refresh);
    TEST_CHECK(decideAction(true, true, true, false) == Action::Refresh);
  }

  void testRequestWithoutPromptWaitsForContent() {
    TEST_CHECK(decideAction(true, false, false, false) == Action::None);
    TEST_CHECK(decideAction(true, true, false, false) == Action::Open);
  }

  // run0 twice in a row (nixos-rebuild): the second request arrives while the
  // panel of the first one plays its close animation. Refreshing that panel made
  // it adopt the new request and cancel it once the animation ended.
  void testRequestDuringCloseAnimationNeverRefreshesClosingPanel() {
    TEST_CHECK(decideAction(true, true, true, true) == Action::Open);
    TEST_CHECK(decideAction(true, false, true, true) == Action::None);
  }

} // namespace

int main() {
  testNoRequestClosesOpenPanel();
  testRequestRefreshesOpenPanel();
  testRequestWithoutPromptWaitsForContent();
  testRequestDuringCloseAnimationNeverRefreshesClosingPanel();
  return 0;
}
