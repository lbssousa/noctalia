#pragma once

#include <string>
#include <string_view>
#include <sys/types.h>

class PamAuthenticator {
public:
  struct [[nodiscard]] Result {
    bool success = false;
    std::string message;
  };

  // Pre-translated texts: authentication runs off the main thread.
  struct Messages {
    std::string startFailed;
    std::string userUnavailable;
    std::string authenticationFailed;
  };

  // A running noctalia-pam-helper the caller waits on with poll() and may cancel.
  struct Helper {
    pid_t pid = -1;
    // Readable once the helper has replied (or died).
    int resultFd = -1;
    // One byte per PAM_TEXT_INFO message; only with securityKey.
    int infoFd = -1;
    bool sentOk = false;
    std::string path;
  };

  Result authenticateCurrentUser(std::string_view password, const Messages& messages) const;

  // Starts the helper and hands it the password. With securityKey it runs the
  // security key service (-Dpam_service_security_key) instead of the lock
  // screen one and reports PAM_TEXT_INFO cues (e.g. pam_u2f's "touch the key")
  // on infoFd.
  [[nodiscard]] static bool spawnHelper(Helper& helper, std::string_view password, bool securityKey);
  // Reads the reply and reaps the helper.
  [[nodiscard]] static Result finishHelper(Helper& helper, const Messages& messages);
  // Kills and reaps the helper, discarding its reply.
  static void cancelHelper(Helper& helper);

  // Whether noctalia was built with a security key PAM service.
  [[nodiscard]] static constexpr bool securityKeyServiceAvailable() {
#ifdef NOCTALIA_PAM_SECURITY_KEY
    return true;
#else
    return false;
#endif
  }

  static std::string currentUsername();
};
