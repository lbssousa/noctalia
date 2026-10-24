#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <string>

class Flex;
class FingerprintManager;
class SecurityKeyManager;

namespace settings {

  // Transient UI state of the Security page blocks that must survive content rebuilds.
  struct SecurityHardwareUiState {
    std::string pendingFingerDelete;
    std::optional<std::size_t> pendingCredentialRemove;
  };

  struct SecurityHardwareActions {
    std::function<void()> requestRebuild;
    std::function<void()> openFingerprintEnrollSheet;
    std::function<void()> openSecurityKeyRegisterSheet;
    std::function<void()> browseGpgPublicKey;
    bool offline = false;
  };

  void buildFingerprintBlock(
      Flex& block, FingerprintManager& manager, SecurityHardwareUiState& state, const SecurityHardwareActions& actions,
      float scale
  );
  // Sheet body: finger picker, then the enrollment progress.
  void
  buildFingerprintEnrollSheet(Flex& body, FingerprintManager& manager, const std::function<void()>& close, float scale);

  void buildFido2Block(
      Flex& block, SecurityKeyManager& manager, SecurityHardwareUiState& state, const SecurityHardwareActions& actions,
      float scale
  );
  void buildFido2RegisterSheet(
      Flex& body, SecurityKeyManager& manager, std::string& pin, const std::function<void()>& close, float scale
  );

  void buildGpgCardBlock(Flex& block, SecurityKeyManager& manager, const SecurityHardwareActions& actions, float scale);

} // namespace settings
