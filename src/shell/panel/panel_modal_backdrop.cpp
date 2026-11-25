#include "shell/panel/panel_modal_backdrop.h"

#include "core/log.h"
#include "shell/wayland/layer_shell.h"
#include "shell/wayland/layer_surface.h"
#include "viewporter-client-protocol.h"
#include "wayland/wayland_connection.h"
#include "wlr-layer-shell-unstable-v1-client-protocol.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace {

  constexpr Logger kLog("panel-modal-backdrop");

  const zwlr_layer_surface_v1_listener kLayerSurfaceListener = {
      .configure = &PanelModalBackdrop::handleConfigure,
      .closed = &PanelModalBackdrop::handleClosed,
  };

  std::uint8_t alphaByte(float dim) {
    return static_cast<std::uint8_t>(std::lround(std::clamp(dim, 0.0F, 1.0F) * 255.0F));
  }

} // namespace

PanelModalBackdrop::~PanelModalBackdrop() {
  deactivate();
  releaseBuffer();
}

void PanelModalBackdrop::initialize(WaylandConnection& wayland) { m_wayland = &wayland; }

void PanelModalBackdrop::releaseBuffer() {
  if (m_buffer != nullptr) {
    wl_buffer_destroy(m_buffer);
    m_buffer = nullptr;
  }
}

bool PanelModalBackdrop::ensureBuffer(std::uint8_t alpha) {
  if (m_buffer != nullptr && m_bufferAlpha == alpha) {
    return true;
  }
  releaseBuffer();
  if (m_wayland == nullptr || m_wayland->shm() == nullptr) {
    return false;
  }

  constexpr std::size_t kSize = 4; // 1×1 ARGB8888
  const int fd = memfd_create("noctalia-modal-backdrop", MFD_CLOEXEC);
  if (fd < 0) {
    kLog.warn("failed to create shm fd: {}", std::strerror(errno));
    return false;
  }
  // Premultiplied black: B, G, R stay 0 and only the alpha byte (little-endian
  // ARGB8888 → memory order B, G, R, A) carries the dim.
  const std::uint8_t pixel[kSize] = {0, 0, 0, alpha};
  if (::write(fd, pixel, kSize) != static_cast<ssize_t>(kSize)) {
    kLog.warn("failed to fill shm buffer: {}", std::strerror(errno));
    ::close(fd);
    return false;
  }

  wl_shm_pool* pool = wl_shm_create_pool(m_wayland->shm(), fd, static_cast<std::int32_t>(kSize));
  ::close(fd);
  if (pool == nullptr) {
    return false;
  }
  m_buffer = wl_shm_pool_create_buffer(pool, 0, 1, 1, 4, WL_SHM_FORMAT_ARGB8888);
  wl_shm_pool_destroy(pool);
  m_bufferAlpha = alpha;
  return m_buffer != nullptr;
}

void PanelModalBackdrop::activate(const std::vector<wl_output*>& outputs, LayerShellLayer layer, float dim) {
  if (m_wayland == nullptr) {
    return;
  }
  const std::uint8_t alpha = alphaByte(dim);
  const auto layerValue = static_cast<std::uint32_t>(layer);
  if (alpha == 0) {
    deactivate();
    return;
  }

  // A reused backdrop must stay below the new panel surface, which is created
  // after this call: keep it only when nothing about it changes.
  const bool sameOutputs = outputs.size() == m_surfaces.size()
      && std::ranges::all_of(outputs, [this](wl_output* output) { return m_surfaces.contains(output); });
  if (isActive() && sameOutputs && m_layer == layerValue && m_bufferAlpha == alpha) {
    return;
  }

  deactivate();
  if (!ensureBuffer(alpha)) {
    kLog.warn("disabled: shm buffer unavailable");
    return;
  }
  if (m_wayland->extension<LayerShell>().manager() == nullptr || m_wayland->compositor() == nullptr) {
    return;
  }
  if (m_wayland->viewporter() == nullptr) {
    kLog.warn("disabled: wp_viewporter not available");
    return;
  }

  m_layer = layerValue;
  for (wl_output* output : outputs) {
    if (output == nullptr || m_surfaces.contains(output)) {
      continue;
    }
    if (auto instance = createInstance(output, layer)) {
      m_surfaces.emplace(output, std::move(instance));
    }
  }
}

std::unique_ptr<PanelModalBackdrop::Instance>
PanelModalBackdrop::createInstance(wl_output* output, LayerShellLayer layer) {
  auto instance = std::make_unique<Instance>();
  instance->owner = this;
  instance->output = output;

  instance->surface = wl_compositor_create_surface(m_wayland->compositor());
  if (instance->surface == nullptr) {
    return nullptr;
  }
  instance->viewport = wp_viewporter_get_viewport(m_wayland->viewporter(), instance->surface);

  instance->layerSurface = zwlr_layer_shell_v1_get_layer_surface(
      m_wayland->extension<LayerShell>().manager(), instance->surface, output, static_cast<std::uint32_t>(layer),
      "noctalia-panel-backdrop"
  );
  if (instance->layerSurface == nullptr) {
    if (instance->viewport != nullptr) {
      wp_viewport_destroy(instance->viewport);
    }
    wl_surface_destroy(instance->surface);
    return nullptr;
  }

  zwlr_layer_surface_v1_add_listener(instance->layerSurface, &kLayerSurfaceListener, instance.get());
  zwlr_layer_surface_v1_set_anchor(
      instance->layerSurface,
      LayerShellAnchor::Top | LayerShellAnchor::Bottom | LayerShellAnchor::Left | LayerShellAnchor::Right
  );
  zwlr_layer_surface_v1_set_size(instance->layerSurface, 0, 0);
  // Cover the bars too: -1 ignores every exclusive zone.
  zwlr_layer_surface_v1_set_exclusive_zone(instance->layerSurface, -1);
  zwlr_layer_surface_v1_set_keyboard_interactivity(
      instance->layerSurface, static_cast<std::uint32_t>(LayerShellKeyboard::None)
  );

  // Click-through for its whole life.
  if (wl_region* emptyRegion = wl_compositor_create_region(m_wayland->compositor()); emptyRegion != nullptr) {
    wl_surface_set_input_region(instance->surface, emptyRegion);
    wl_region_destroy(emptyRegion);
  }

  // Initial commit without a buffer starts the layer-shell configure round-trip.
  wl_surface_commit(instance->surface);
  return instance;
}

void PanelModalBackdrop::deactivate() {
  for (auto& [output, instance] : m_surfaces) {
    if (instance) {
      destroyInstance(*instance);
    }
  }
  m_surfaces.clear();
}

void PanelModalBackdrop::destroyInstance(Instance& instance) {
  if (instance.viewport != nullptr) {
    wp_viewport_destroy(instance.viewport);
    instance.viewport = nullptr;
  }
  if (instance.layerSurface != nullptr) {
    zwlr_layer_surface_v1_destroy(instance.layerSurface);
    instance.layerSurface = nullptr;
  }
  if (instance.surface != nullptr) {
    wl_surface_destroy(instance.surface);
    instance.surface = nullptr;
  }
}

void PanelModalBackdrop::handleConfigure(
    void* data, zwlr_layer_surface_v1* layerSurface, std::uint32_t serial, std::uint32_t width, std::uint32_t height
) {
  zwlr_layer_surface_v1_ack_configure(layerSurface, serial);
  auto* instance = static_cast<Instance*>(data);
  if (instance == nullptr || instance->owner == nullptr) {
    return;
  }
  instance->owner->applyConfigured(*instance, width, height);
}

void PanelModalBackdrop::handleClosed(void* data, zwlr_layer_surface_v1* /*layerSurface*/) {
  auto* instance = static_cast<Instance*>(data);
  if (instance == nullptr || instance->owner == nullptr) {
    return;
  }
  PanelModalBackdrop* owner = instance->owner;
  auto it = owner->m_surfaces.find(instance->output);
  if (it != owner->m_surfaces.end() && it->second.get() == instance) {
    owner->destroyInstance(*it->second);
    owner->m_surfaces.erase(it);
  }
}

void PanelModalBackdrop::applyConfigured(Instance& instance, std::uint32_t width, std::uint32_t height) {
  if (instance.surface == nullptr) {
    return;
  }
  if (!instance.bufferAttached && m_buffer != nullptr) {
    wl_surface_attach(instance.surface, m_buffer, 0, 0);
    wl_surface_set_buffer_scale(instance.surface, 1);
    wl_surface_damage_buffer(instance.surface, 0, 0, 1, 1);
    instance.bufferAttached = true;
  }
  if (instance.viewport != nullptr && width > 0 && height > 0) {
    wp_viewport_set_destination(instance.viewport, static_cast<std::int32_t>(width), static_cast<std::int32_t>(height));
  }
  wl_surface_commit(instance.surface);
}
