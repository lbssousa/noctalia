#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

// Text helpers shared by the authentication surfaces (polkit panel, lock screen).
namespace auth_text {

  // What a PAM info/error message asks the user to do, beyond typing.
  enum class AuthCue { None, Fingerprint, SecurityKey };

  // pam_fprintd prompts and errors (gettext: English or the system locale, here
  // pt_BR) and the pam_u2f cue ("Please touch the FIDO authenticator.", not translated).
  inline AuthCue classifyPamMessage(std::string_view text) {
    std::string lower(text);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    const auto contains = [&lower](std::string_view needle) { return lower.find(needle) != std::string::npos; };
    if (contains("finger") || contains("dedo") || contains("impressão digital")) {
      return AuthCue::Fingerprint;
    }
    if (contains("touch the") || contains("fido") || contains("security key") || contains("toque")) {
      return AuthCue::SecurityKey;
    }
    return AuthCue::None;
  }

} // namespace auth_text
