"""
Prototype API for in-tool Python scripts (Channeler hex editor).

Scripts run in the UI thread with a restricted namespace: ``ch`` / ``channeler`` expose
ROM helpers, TOML data, and address/symbol utilities used elsewhere in the editor.

**Why run inside Channeler?** ``ch`` / ``channeler`` read and write the **ROM buffer that is
open in the editor** (and see the same TOML/anchors as the UI). A script on disk must open the
``.gba`` path, keep it in sync with saves, and cannot mark the editor dirty or refresh views.

The full ``editors.common.hex_editor`` and ``editors.common.gba_graphics`` modules are injected
as ``hex_editor`` and ``gba_graphics``. Common helpers are also copied to the **top level** (e.g.
``parse_rom_file_offset``, ``resolve_gba_pointer``) so short scripts do not need prefixes.

You can also use normal imports in your script text, e.g.
``from hex_editor import parse_rom_file_offset`` — the name ``hex_editor`` is the module in the
script namespace.

Those modules are imported **inside** :func:`run_user_script` (not at import time) so loading
``channeler_script_api`` does not create a circular import with ``hex_editor.py``.

**Caveats:** scripts still run on the **UI thread**; avoid blocking work. You can call private
names (``_foo``) or types that open dialogs—use judgment. The open ROM is ``ch`` / ``channeler``,
not a global on those modules.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable, Dict, Optional

# Mirror ``hex_editor`` GBA constants (avoid importing hex_editor from this module).
GBA_ROM_BASE = 0x08000000
GBA_ROM_MAX = 0x09FFFFFF
GBA_EWRAM_START = 0x02000000
GBA_EWRAM_END = 0x0203FFFF
GBA_IWRAM_START = 0x03000000
GBA_IWRAM_END = 0x03007FFF

LogFn = Callable[[str], None]

# Copied into each script run's globals so users can call ``parse_rom_file_offset(...)`` etc.
# without ``hex_editor.`` / ``gba_graphics.`` prefixes. Keep this list short and stable.
_HEX_EDITOR_FLAT_NAMES = (
    "parse_rom_file_offset",
    "load_pokefirered_sym_name_to_addr",
    "load_pokefirered_sym_norm_to_name",
    "normalize_named_anchor_lookup_key",
    "normalize_named_anchor_format",
    "encode_pcs_string",
    "decode_pcs_string_view",
    "decode_ascii_slot",
    "thumb2_bl_immediate_target_gba",
)
_GBA_GRAPHICS_FLAT_NAMES = ("resolve_gba_pointer",)


def _inject_flat_module_names(
    ns: Dict[str, Any],
    hex_editor_mod: Any,
    gba_graphics_mod: Any,
) -> None:
    for name in _HEX_EDITOR_FLAT_NAMES:
        if hasattr(hex_editor_mod, name):
            ns[name] = getattr(hex_editor_mod, name)
    for name in _GBA_GRAPHICS_FLAT_NAMES:
        if hasattr(gba_graphics_mod, name):
            ns[name] = getattr(gba_graphics_mod, name)


class ChannelerScriptAPI:
    """Bound to a single :class:`HexEditorFrame` for one script run."""

    def __init__(self, hex_editor: Any, log: LogFn) -> None:
        self._hex = hex_editor
        self._log = log

    # ── logging ─────────────────────────────────────────────

    def log(self, *args: Any, sep: str = " ", end: str = "\n") -> None:
        """Append a line to the script output pane (same thread as Tk)."""
        self._log(sep.join(str(a) for a in args) + end)

    # ── ROM ─────────────────────────────────────────────────

    @property
    def rom_size(self) -> int:
        return len(self._hex._data)

    def read_bytes(self, file_offset: int, n: int) -> bytes:
        if file_offset < 0 or n < 0 or file_offset + n > len(self._hex._data):
            raise IndexError(f"read_bytes({file_offset}, {n}) out of range for ROM size {self.rom_size}")
        return bytes(self._hex._data[file_offset : file_offset + n])

    def read_u8(self, file_offset: int) -> int:
        return self.read_bytes(file_offset, 1)[0]

    def read_u16_le(self, file_offset: int) -> int:
        b = self.read_bytes(file_offset, 2)
        return b[0] | (b[1] << 8)

    def read_u32_le(self, file_offset: int) -> int:
        b = self.read_bytes(file_offset, 4)
        return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

    def write_bytes(self, file_offset: int, data: bytes) -> None:
        if file_offset < 0 or file_offset + len(data) > len(self._hex._data):
            raise IndexError("write_bytes range out of ROM bounds")
        self._hex._data[file_offset : file_offset + len(data)] = data
        self._hex._modified = True
        self._hex._ldr_pc_targets_valid = False
        self._hex._schedule_xref_rebuild()

    def write_u32_le(self, file_offset: int, value: int) -> None:
        self.write_bytes(file_offset, value & 0xFFFFFFFF)

    # ── TOML / anchors ──────────────────────────────────────

    @property
    def toml(self) -> Dict[str, Any]:
        """Shallow copy of loaded TOML tables (FunctionAnchors, NamedAnchors, …)."""
        return dict(self._hex._toml_data) if self._hex._toml_data else {}

    @property
    def toml_path(self) -> Optional[str]:
        return getattr(self._hex, "_toml_path", None)

    def resolve(self, text: str) -> tuple:
        """``(file_offset_or_None, error_message)`` — same as Goto / NamedAnchor resolution."""
        return self._hex.resolve_file_offset_or_named_anchor(text.strip())

    # ── Addresses / symbols (decompiler-style) ─────────────

    def file_offset_to_gba(self, file_offset: int) -> int:
        return GBA_ROM_BASE + file_offset

    def gba_to_file_offset(self, gba_addr: int) -> Optional[int]:
        if GBA_ROM_BASE <= gba_addr <= GBA_ROM_MAX:
            return gba_addr - GBA_ROM_BASE
        return None

    def label_for_gba(self, gba_addr: int) -> Optional[str]:
        """Merged ``pokefirered.sym`` + TOML anchor names (normalized Thumb address)."""
        merged = self._hex._merged_sub_name_map()
        return merged.get(gba_addr & ~1)

    def label_for_rom_pointer_word(self, word_le: int) -> str:
        """Format a 32-bit little-endian ROM pointer word as ``Name`` or ``0x…`` (UI-style)."""
        if not (GBA_ROM_BASE <= word_le <= GBA_ROM_MAX):
            return f"0x{word_le & 0xFFFFFFFF:08X}"
        lab = self.label_for_gba(word_le)
        return lab if lab else f"0x{word_le:08X}"

    def classify_gba(self, gba_addr: int) -> str:
        """``rom`` | ``ewram`` | ``iwram`` | ``other`` — mirrors syntax-highlight regions."""
        tag = self._hex._classify_gba_address(gba_addr)
        if tag == "addr_rom":
            return "rom"
        if tag == "addr_ewram":
            return "ewram"
        if tag == "addr_iwram":
            return "iwram"
        return "other"

    def sym_name_to_addr(self) -> Dict[str, int]:
        """Full ``pokefirered.sym`` name → address map when the open ROM is FireRed (``BPRE``); else empty."""
        return self._hex.get_pokefirered_sym_name_to_addr()


def run_user_script(
    source: str,
    hex_editor: Any,
    log: LogFn,
) -> str:
    """
    Execute *source* with a Channeler API namespace. Returns non-empty string
    on failure (traceback text); empty on success. Does not raise on script errors.
    """
    api = ChannelerScriptAPI(hex_editor, log)

    # Lazy import: ``hex_editor`` package imports this module; importing ``hex_editor`` here only
    # after the app has finished loading avoids circular-import issues.
    import editors.common.gba_graphics as gba_graphics
    import editors.common.hex_editor as hex_editor_mod

    ns: Dict[str, Any] = {
        "__name__": "__channeler_script__",
        "__builtins__": __builtins__,
        "ch": api,
        "channeler": api,
        "hex_editor": hex_editor_mod,
        "gba_graphics": gba_graphics,
        "GBA_ROM_BASE": GBA_ROM_BASE,
        "GBA_ROM_MAX": GBA_ROM_MAX,
        "GBA_EWRAM_START": GBA_EWRAM_START,
        "GBA_EWRAM_END": GBA_EWRAM_END,
        "GBA_IWRAM_START": GBA_IWRAM_START,
        "GBA_IWRAM_END": GBA_IWRAM_END,
    }
    _inject_flat_module_names(ns, hex_editor_mod, gba_graphics)
    try:
        code = compile(source, "<channeler_script>", "exec")
        exec(code, ns, ns)
        log("— finished without exception —\n")
    except Exception:
        log("— exception —\n")
        tb = traceback.format_exc()
        log(tb)
        return tb
    return ""


def format_run_header() -> str:
    import datetime

    return f"=== Channeler script run {datetime.datetime.now().isoformat(timespec='seconds')} ===\n"
