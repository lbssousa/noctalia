#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Pure parsers and formatters behind SecurityKeyManager: the output of fido2-token, pamu2fcfg and
// gpg, pam_u2f's PAM lines, resident SSH key files and the ~/.ssh/config.d drop-ins written for
// the git hosts those keys name. No I/O here, so all of it is unit tested.
namespace security_hw {

  using Bytes = std::vector<std::uint8_t>;

  [[nodiscard]] std::vector<std::string> splitLines(std::string_view text);
  [[nodiscard]] std::string lastLine(std::string_view text);
  // Base64 as Python's b64decode(validate=True): only the alphabet, padding only at the end.
  [[nodiscard]] std::optional<Bytes> decodeBase64Strict(std::string_view text);

  // -- FIDO2/U2F --------------------------------------------------------------------------------

  struct FidoDevice {
    std::string path;
    std::string name;
    bool residentKeys = false; // "rk": keeps resident credentials (SSH keys)
    bool clientPin = false;    // a PIN is set
    int pinRetries = -1;       // -1 when unknown
  };

  // `fido2-token -L`: "/dev/hidraw1: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)".
  [[nodiscard]] std::vector<FidoDevice> parseFidoDevices(std::string_view text);
  // `fido2-token -I <dev>`: the "options" and "pin retries" lines, into <device>.
  void applyFidoInfo(FidoDevice& device, std::string_view text);

  // The credentials on <user>'s line of a pam_u2f authfile ("user:cred[:cred…]").
  [[nodiscard]] std::vector<std::string> credentialHandles(std::string_view line, std::string_view user);
  // "keyHandle,publicKey,coseType,options" → keyHandle.
  [[nodiscard]] std::string credentialKeyHandle(std::string_view credential);
  // A short, stable prefix of the key handle that tells two keys apart.
  [[nodiscard]] std::string credentialLabel(std::string_view credential);
  // Appends the credentials not on the list yet, by key handle.
  [[nodiscard]] std::vector<std::string>
  mergeCredentials(const std::vector<std::string>& existing, const std::vector<std::string>& added);

  struct PamU2f {
    bool u2f = false;     // the file uses pam_u2f
    std::string authfile; // "authfile=…", empty for pam_u2f's per-user default
    bool pin = false;     // pinverification=1
  };
  [[nodiscard]] PamU2f parsePamU2f(std::string_view text);

  // Where a key registered now would go, and whether sudo and polkit would read it.
  enum class FidoTargetKind {
    Own,       // the user's own list (pam_u2f's default), which they read
    NoPam,     // neither asks for a key
    OtherFile, // they read a file this page doesn't write (authfile=…)
    Mixed,     // they read different files, so a key would only work for one
  };
  struct FidoTarget {
    FidoTargetKind kind = FidoTargetKind::NoPam;
    std::string path;
  };
  // <services>: the pam_u2f state of sudo and polkit-1; <ownAuthfile>: pam_u2f's per-user default.
  [[nodiscard]] FidoTarget fidoTarget(const std::vector<PamU2f>& services, std::string_view ownAuthfile);
  [[nodiscard]] bool pamUsesFile(const std::vector<PamU2f>& services, std::string_view path, std::string_view own);

  // libfido2's errors, as pamu2fcfg, fido2-token and ssh-keygen print them, to an error code:
  // pin-invalid, pin-blocked, pin-required, timeout, no-device, ssh-none, or generic.
  [[nodiscard]] std::string fidoErrorCode(std::string_view text, bool pinGiven);

  // -- OpenPGP ----------------------------------------------------------------------------------

  // Whether a `gpg --list-secret-keys --with-colons` listing has a secret part kept in the
  // keyring rather than on a card (field 15: the card serial for a stub, "#" for a stub whose
  // card is away, "+" or empty for a real secret).
  [[nodiscard]] bool secretOnDisk(std::string_view colons);
  // gpg's own grouping: ten blocks of four, with an extra space in the middle.
  [[nodiscard]] std::string formatFingerprint(std::string_view fpr);

  // -- Resident SSH keys ------------------------------------------------------------------------

  inline constexpr int kMaxPersistMinutes = 1440;
  inline constexpr std::string_view kSshInclude = "Include config.d/*.conf";
  inline constexpr std::string_view kControlDir = "noctalia-security-hw/control";

  struct SkPublic {
    std::string type;        // "ed25519-sk" or "ecdsa-sk"
    std::string application; // "ssh:…"
    Bytes blob;
  };
  // A resident key's .pub line.
  [[nodiscard]] std::optional<SkPublic> parseSkPublic(std::string_view text);
  // The SHA256 fingerprint ssh-keygen -l prints for a public blob.
  [[nodiscard]] std::string sshFingerprint(const Bytes& blob);

  struct SkHandle {
    Bytes blob;
    bool encrypted = false;
    Bytes credential; // the key handle (credential ID); empty when encrypted
  };
  // A resident key's private file (the handle ssh-keygen writes, not a secret).
  [[nodiscard]] std::optional<SkHandle> parseSkHandle(std::string_view text);

  struct TokenCredential {
    std::string id; // base64, as fido2-token prints it
    Bytes raw;
  };
  // `fido2-token -L -k <application>`: "NN: <credential id> <display name…> <user id> <type> <prot>".
  [[nodiscard]] std::vector<TokenCredential> parseTokenCredentials(std::string_view text);

  // Whether <name> in ~/.ssh is the private half of a resident key copy.
  [[nodiscard]] bool isResidentKeyName(std::string_view name);
  // The file name `ssh-keygen -K` gives a key, so importing it again finds it.
  [[nodiscard]] std::string
  residentKeyName(std::string_view algorithm, std::string_view application, std::string_view user);
  // The FIDO2 user ID `ssh-keygen -K` put in a copy's file name, or "".
  [[nodiscard]] std::string
  residentKeyUser(std::string_view name, std::string_view keyType, std::string_view application);

  struct SshCreateOptions {
    std::string algorithm = "ed25519-sk";
    std::string application; // after "ssh:"
    std::string user;
    std::string comment;
    bool verify = true; // PIN for every use
    bool touch = true;  // touch for every use
    bool replace = false;
  };
  // Why a new key's options can't be used: "" when they can, else algorithm, application, user,
  // pub-name or comment. Checked before the key is touched, so nothing half-made stays on it.
  [[nodiscard]] std::string sshCreateProblem(const SshCreateOptions& options);
  [[nodiscard]] std::vector<std::string> sshCreateCommand(const std::string& path, const SshCreateOptions& options);

  struct GitRemote {
    std::string login;
    std::string host;
    std::string port; // "" for the default
    bool operator==(const GitRemote&) const = default;
  };
  // The git host a resident key's application names (ssh:github.com, ssh:login@host:port): only
  // well-known forges, or hosts with "git" in a label before the top-level domain.
  [[nodiscard]] std::optional<GitRemote> gitRemote(std::string_view application);

  // A drop-in for <remote>'s keys. 0 minutes turns connection reuse off explicitly; a value
  // reuses an authenticated master that long; nullopt leaves the Control lines out.
  [[nodiscard]] std::string
  dropInText(const std::vector<std::string>& names, const GitRemote& remote, std::optional<int> minutes);
  enum class DropInKind { Missing, Ours, Edited, Foreign };
  struct DropIn {
    DropInKind kind = DropInKind::Missing;
    std::vector<std::string> names;
    GitRemote remote;
    std::optional<int> minutes;
  };
  // A drop-in this page (or the security-hardware plugin before it) wrote: Ours; Edited when it
  // was changed since; Foreign when it isn't one of ours.
  [[nodiscard]] DropIn parseDropIn(std::string_view text);
  // Whether an ssh config includes config.d already (home-manager writes
  // "Include ~/.ssh/config.d/*.conf").
  [[nodiscard]] bool includesDropIns(std::string_view config);
  [[nodiscard]] bool validPersistMinutes(int minutes);

} // namespace security_hw
