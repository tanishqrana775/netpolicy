"""Modern CLI UX styling, banner, and telemetry presentation for netpolicy."""

from __future__ import annotations

from netpolicy.ui.banner import (
    GRADIENT_STOPS,
    TIPS,
    build_logo,
    detect_environment,
    detect_privilege,
    get_ui_console,
    interpolate_gradient,
    mix_toward_white,
    print_compact_header,
    print_footer,
    print_welcome,
    render_animation,
    render_static_banner,
    set_global_no_banner,
    should_show_banner,
    sweep_frames,
    ui_session,
)
from netpolicy.ui.wsl import (
    distro_installed,
    distro_name,
    is_native_windows,
    is_wsl,
    maybe_launch_wsl,
    wsl_available,
)

__all__ = [
    "GRADIENT_STOPS",
    "TIPS",
    "build_logo",
    "detect_environment",
    "detect_privilege",
    "distro_installed",
    "distro_name",
    "get_ui_console",
    "interpolate_gradient",
    "is_native_windows",
    "is_wsl",
    "maybe_launch_wsl",
    "mix_toward_white",
    "print_compact_header",
    "print_footer",
    "print_welcome",
    "render_animation",
    "render_static_banner",
    "set_global_no_banner",
    "should_show_banner",
    "sweep_frames",
    "ui_session",
    "wsl_available",
]
