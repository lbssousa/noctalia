#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

class WaylandConnection;
enum class LayerShellLayer : std::uint32_t;
struct wl_buffer;
struct wl_output;
struct wl_surface;
struct wp_viewport;
struct zwlr_layer_surface_v1;

// Fullscreen layer-shell surfaces (one per output, namespace
// "noctalia-panel-backdrop") that darken the screen behind a modal panel: the
// polkit prompt and plugin panels with `modal = true` (pinentry, ssh-askpass).
// The namespace lets the compositor blur what is behind it as well (Umbriel
// `[[layer_rule]]`, Hyprland `layerrule`).
//
// Created on the panel's layer before the panel surface, so the panel stacks
// above it. Click-through (empty input region) and never takes keyboard focus:
// the panel's own exclusive keyboard focus is what makes the prompt modal, and
// pointer routing does not depend on how a compositor orders same-layer
// surfaces.
//
// Same buffer strategy as PanelClickShield: one shared 1×1 ARGB8888 SHM buffer
// (premultiplied black at the configured alpha) stretched by wp_viewport.
class PanelModalBackdrop {
public:
  PanelModalBackdrop() = default;
  ~PanelModalBackdrop();

  PanelModalBackdrop(const PanelModalBackdrop&) = delete;
  PanelModalBackdrop& operator=(const PanelModalBackdrop&) = delete;

  void initialize(WaylandConnection& wayland);

  // Maps the backdrop on the given outputs. Keeps the surfaces already mapped with
  // the same layer and dim (a chained prompt reuses them without flicker).
  void activate(const std::vector<wl_output*>& outputs, LayerShellLayer layer, float dim);
  // Tears down all surfaces. Idempotent.
  void deactivate();

  bool isActive() const noexcept { return !m_surfaces.empty(); }

  static void handleConfigure(
      void* data, zwlr_layer_surface_v1* layerSurface, std::uint32_t serial, std::uint32_t width, std::uint32_t height
  );
  static void handleClosed(void* data, zwlr_layer_surface_v1* layerSurface);

private:
  struct Instance {
    PanelModalBackdrop* owner = nullptr;
    wl_output* output = nullptr;
    wl_surface* surface = nullptr;
    zwlr_layer_surface_v1* layerSurface = nullptr;
    wp_viewport* viewport = nullptr;
    bool bufferAttached = false;
  };

  bool ensureBuffer(std::uint8_t alpha);
  void releaseBuffer();
  std::unique_ptr<Instance> createInstance(wl_output* output, LayerShellLayer layer);
  void destroyInstance(Instance& instance);
  void applyConfigured(Instance& instance, std::uint32_t width, std::uint32_t height);

  WaylandConnection* m_wayland = nullptr;
  wl_buffer* m_buffer = nullptr;
  std::uint8_t m_bufferAlpha = 0;
  std::uint32_t m_layer = 0;
  std::unordered_map<wl_output*, std::unique_ptr<Instance>> m_surfaces;
};
