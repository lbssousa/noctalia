#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

class PamAuthenticator {
public:
  struct Result {
    bool success = false;
    std::string message;
  };

  // A PAM helper process that the caller waits on with poll() and may cancel.
  struct Helper {
    pid_t pid = -1;
    // Readable once the helper has finished.
    int resultFd = -1;
    // One byte per PAM_TEXT_INFO message (only when spawned with notifyInfo).
    int infoFd = -1;
  };

  [[nodiscard]] Result authenticateCurrentUser(
      std::string_view password, std::string_view service, std::string_view language,
      std::string_view startFailureMessage
  ) const;
  [[nodiscard]] static bool spawnHelper(
      Helper& helper, std::string_view password, std::string_view service, std::string_view language, bool notifyInfo
  );
  // Reads the result and reaps the helper; false if it failed to report one.
  [[nodiscard]] static bool finishHelper(Helper& helper, Result& result);
  // Kills and reaps the helper, discarding its result.
  static void cancelHelper(Helper& helper);
  [[nodiscard]] static std::string currentUsername();
  [[nodiscard]] static int runHelperMode(int argc, char* argv[]);
};
