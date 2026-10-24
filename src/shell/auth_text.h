#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

// Text helpers shared by the authentication panels (polkit, secret prompt).
namespace auth_text {

  // Estimated wrapped line count, capped at maxLines; drives the panel's preferred height.
  inline int wrappedLineCount(std::string_view text, int charsPerLine, int maxLines) {
    if (text.empty()) {
      return 0;
    }
    int lines = 0;
    int col = 0;
    for (char ch : text) {
      if (ch == '\n') {
        ++lines;
        col = 0;
        if (lines >= maxLines) {
          return maxLines;
        }
        continue;
      }
      ++col;
      if (charsPerLine > 0 && col > charsPerLine) {
        ++lines;
        col = 1;
        if (lines >= maxLines) {
          return maxLines;
        }
      }
    }
    if (col > 0 || lines == 0) {
      ++lines;
    }
    return std::min(lines, maxLines);
  }

  // Breaks unbreakable runs (paths, fingerprints) so the label can wrap them.
  inline std::string wrapLongRuns(std::string text, std::size_t maxRun = 48) {
    std::string out;
    out.reserve(text.size() + text.size() / maxRun);
    std::size_t run = 0;
    for (char ch : text) {
      const bool breakable = std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == '/' || ch == ':' || ch == '-';
      out.push_back(ch);
      if (breakable) {
        run = 0;
        continue;
      }
      ++run;
      if (run >= maxRun) {
        out.push_back('\n');
        run = 0;
      }
    }
    return out;
  }

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
