"""
Prototype API for in-tool Python scripts (Channeler hex editor).

Scripts run in the UI thread with a restricted namespace: ``ch`` / ``channeler`` expose
ROM helpers, TOML data, and address/symbol utilities used elsewhere in the editor.
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
        """Full ``pokefirered.sym`` name → address map (lazy load from repo root)."""
        from editors.common.hex_editor import load_pokefirered_sym_name_to_addr

        return load_pokefirered_sym_name_to_addr()


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

    ns: Dict[str, Any] = {
        "__name__": "__channeler_script__",
        "__builtins__": __builtins__,
        "ch": api,
        "channeler": api,
        "GBA_ROM_BASE": GBA_ROM_BASE,
        "GBA_ROM_MAX": GBA_ROM_MAX,
        "GBA_EWRAM_START": GBA_EWRAM_START,
        "GBA_EWRAM_END": GBA_EWRAM_END,
        "GBA_IWRAM_START": GBA_IWRAM_START,
        "GBA_IWRAM_END": GBA_IWRAM_END,
    }
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
