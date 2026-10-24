#pragma once

// Wire format between the shell and noctalia-pam-helper.
//
// shell -> helper (stdin):  u8 version, u32 length, password bytes
// helper -> shell (stdout): u8 version, u8 Status, i32 PAM return code
//
// Both sides lead with kProtocolVersion so a running shell and a helper from
// a newer package fail cleanly instead of misreading each other. On a version
// mismatch the helper replies with its version only. The helper exits 0 on
// success, 1 on a reported failure and 2 on a protocol error.
//
// With the single argument kSecurityKeyArg (only in builds with
// -Dpam_service_security_key), the helper runs that service instead of the
// lock screen one and writes one byte to kInfoFd for every PAM_TEXT_INFO
// message (kInfoCue: pam_u2f's cue that an enrolled key waits for a touch).
// The "password" sent is then the key's PIN, if any: when pam_u2f asks for a
// PIN (a credential registered with +pin, or pinverification=1) and none was
// sent, the helper writes kInfoPinWanted and refuses the prompt, so pam_u2f
// fails without trying an empty PIN on the key (that would use up a retry).
// Both services are fixed at build time; the shell only picks one of them.

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <unistd.h>

namespace pam_helper {

  constexpr std::uint8_t kProtocolVersion = 1;
  constexpr std::size_t kMaxPasswordBytes = 64 * 1024;

  enum class Status : std::uint8_t {
    Success = 0,
    Failed = 1,
    UserUnavailable = 2,
    StartFailed = 3,
  };

  constexpr Status kLastStatus = Status::StartFailed;

  constexpr int kExitSuccess = 0;
  constexpr int kExitFailure = 1;
  constexpr int kExitProtocolError = 2;

  constexpr const char* kSecurityKeyArg = "--security-key";
  constexpr int kInfoFd = 3;
  constexpr char kInfoCue = 'i';
  constexpr char kInfoPinWanted = 'p';

  [[nodiscard]] inline bool writeAll(int fd, const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = len;
    while (remaining > 0) {
      const ssize_t n = ::write(fd, bytes, remaining);
      if (n > 0) {
        bytes += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] inline bool readAll(int fd, void* data, std::size_t len) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t remaining = len;
    while (remaining > 0) {
      const ssize_t n = ::read(fd, bytes, remaining);
      if (n > 0) {
        bytes += static_cast<std::size_t>(n);
        remaining -= static_cast<std::size_t>(n);
      } else if (n < 0 && errno == EINTR) {
        continue;
      } else {
        return false;
      }
    }
    return true;
  }

} // namespace pam_helper
