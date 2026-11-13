"""The address model for one mapped module.

Why this module exists
----------------------
Two half-models already existed and did not know about each other:

  * `elfinfo.ElfInfo`  — what the FILE says (p_vaddr, p_offset, BSS bounds), all
                         in ELF vaddr space.
  * `mapsview.ModuleView` — what the PROCESS says (mapping start/end, the page
                         -aligned file_offset the kernel reports).

Neither can answer "where does this vaddr live right now". That answer needs
both halves plus three facts that were previously re-derived inline at every
call site:

  1. the module base (the runtime address of vaddr 0). It is *not* always
     `ElfInfo.load_bias`: a prelinked PIE has load_bias 0x200000 while its first
     mapping sits at 0x400000, so subtracting the wrong one shifts everything.
  2. whether a single anchor is provable. Mirror segments and multi-anchor
     layouts (several off-0 segments with different `start - file_offset`) make
     a single base meaningless; the per-segment anchor is the truth there.
  3. that `.bss` is NOBITS — it has no file offset and lives in an anonymous
     mapping after the last file-backed segment, so no file-offset arithmetic
     can express it.

Before this module those facts were spread over 39 lines in 11 functions in
`analysis.py`, and a fix applied to one copy did not reach the others (a real
incident: the p_align fix landed in `elfinfo` while an inline copy in
`analysis.py` kept producing addresses that were off by 0x2000).

Coordinate spaces, stated once
------------------------------
    elf_vaddr    readelf/IDA numbers; what ElfInfo carries
    runtime      an address in this process; what mapsview carries
    file_offset  byte offset into the on-disk file; page-aligned in maps

Every public method below says which space it takes and returns. That naming is
the point of the module: a caller should never have to infer it.

Not cached, deliberately. Building a model costs one 4 KiB read (~5 ms on the
measured device) and caching would introduce an invalidation problem — process
restart, remap, a `.bss` mapping that appears or moves — of exactly the kind
that already produced a false `not_found` when a cached target handle outlived
its connection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .elfinfo import ElfInfo, ElfParseError, parse_elf64
from .mapsview import MapsView, ModuleView, Segment

HEADER_READ_SIZE = 0x1000


class AddressModelError(Exception):
    """The module's addresses cannot be modelled from what we have.

    Distinguishes two cases via `unavailable`, because they call for different
    responses: an unreadable header is worth retrying, an unparseable one means
    the module name is probably wrong.
    """

    def __init__(self, detail: str, *, unavailable: bool) -> None:
        super().__init__(detail)
        self.detail = detail
        self.unavailable = unavailable


@dataclass(slots=True)
class AddressModel:
    """Both halves of one module's address story, plus the derived base."""

    pid: int
    module: str
    elf: ElfInfo
    view: ModuleView
    base: int                   # runtime address of ELF vaddr 0
    base_is_ambiguous: bool     # several off-0 anchors disagreed
    segments: list[Segment] = field(default_factory=list)

    # -- construction -------------------------------------------------------

    @classmethod
    def build(cls, pid: int, module: str, maps: list[Any],
              mem_read) -> "AddressModel":
        """Read the module's ELF header once and combine it with its mappings.

        `mem_read(pid, addr, size) -> bytes` is passed in rather than reached
        for, so the model can be built from a recorded dump in tests.
        """
        view = MapsView.from_maps(maps)
        mod = view.modules.get(module)
        if mod is None:
            raise AddressModelError(f"module {module!r} not mapped in pid {pid}",
                                    unavailable=False)
        segs = [s for s in mod.segments if not s.mirror] or mod.segments
        if not segs:
            raise AddressModelError(f"module {module!r} has no segments",
                                    unavailable=False)

        first = segs[0]
        try:
            header = mem_read(pid, first.start,
                              min(HEADER_READ_SIZE, first.size))
        except Exception as exc:  # noqa: BLE001 - transport-agnostic by design
            raise AddressModelError(
                f"cannot read ELF header of {module!r} at 0x{first.start:x}: {exc}",
                unavailable=True) from exc
        try:
            elf = parse_elf64(header, allow_zero_magic=True)
        except ElfParseError as exc:
            raise AddressModelError(
                f"{module!r} does not parse as ELF64: {exc}",
                unavailable=False) from exc

        # Anchors come from the module's own mappings. MapsView has no flat
        # `segments` (that was a mistake caught by the tests); the segments live
        # on the ModuleView.
        anchors = {s.start - s.file_offset for s in mod.segments
                   if s.file_offset == 0 and not s.mirror}
        ambiguous = len(anchors) > 1
        if len(anchors) == 1:
            base = anchors.pop()
        elif not anchors:
            # No off-0 segment: derive the base from ELF arithmetic. This is the
            # only case where `first_map - load_bias` is correct — and it is
            # wrong whenever a prelinked PIE's first mapping is not at
            # `load_bias`, which is exactly why it is the fallback and not the
            # primary.
            base = first.start - elf.load_bias
        else:
            # Several disagreeing anchors: no single base is provable. Fall back
            # to the first mapping so arithmetic still terminates, and let
            # callers see the ambiguity rather than hide it.
            base = first.start

        return cls(pid=pid, module=module, elf=elf, view=mod, base=base,
                   base_is_ambiguous=ambiguous, segments=segs)

    # -- classification -----------------------------------------------------

    def is_bss(self, elf_vaddr: int) -> bool:
        """Is this ELF vaddr inside the NOBITS tail?"""
        return self.elf.bss_start <= elf_vaddr < self.elf.bss_end

    def is_runtime_addr(self, value: int) -> bool:
        """Does this value already look like a runtime address of this module?

        Used to accept both "you gave me a vaddr" and "you pasted the address
        IDA shows". The window must include `.bss`, which sits *past* the last
        mapping's end, or a runtime `.bss` address is misread as a vaddr and
        shifted twice.
        """
        lo = min(s.start for s in self.view.segments)
        hi = max(s.end for s in self.view.segments)
        hi = max(hi, self.to_runtime(self.elf.bss_end))
        return lo <= value < hi

    # -- conversions --------------------------------------------------------

    def to_runtime(self, elf_vaddr: int) -> int:
        """ELF vaddr -> runtime address.

        `.bss` is handled by the caller (it needs the live anonymous mapping);
        see `_resolve_bss_bounds`, which this module deliberately does not own
        yet — it needs the maps snapshot and is the next migration step.
        """
        return self.base + (elf_vaddr - self.elf.load_bias)

    def segment_for_runtime(self, runtime: int) -> Segment | None:
        for s in self.segments:
            if s.start <= runtime < s.end:
                return s
        return None

    def runtime_to_file_offset(self, runtime: int) -> int | None:
        """Runtime address -> file offset (page-aligned), or None if unmapped."""
        seg = self.segment_for_runtime(runtime)
        if seg is None:
            return None
        return runtime - seg.start + seg.file_offset

    def file_offset_to_runtime(self, file_offset: int) -> int | None:
        """File offset -> runtime address, following `mapsview`'s convention."""
        return self.view.runtime_of(file_offset)

    def bearing_translation_base(self, file_offset: int) -> int | None:
        """The per-segment anchor for the segment holding this file offset.

        This is the value that appears as `translation_base` in tool output. It
        is `start - file_offset`, so the identity it satisfies is
        `start == translation_base + file_offset` — NOT `+ vaddr`. Getting that
        backwards was one of this project's recorded mistakes.
        """
        for s in self.segments:
            if s.file_offset <= file_offset < s.file_offset + s.size:
                return s.start - s.file_offset
        return None

    # -- description --------------------------------------------------------

    def describe(self) -> dict[str, Any]:
        """The `load_bias` / `translation_base` fields tools report."""
        return {
            "load_bias": f"0x{self.base:x}",
            "load_bias_ambiguous": self.base_is_ambiguous,
            "elf_load_bias": f"0x{self.elf.load_bias:x}",
            "segments": [
                {
                    "start": f"0x{s.start:x}",
                    "end": f"0x{s.end:x}",
                    "file_offset": f"0x{s.file_offset:x}",
                    "permissions": s.flags_str(),
                    "translation_base": f"0x{s.start - s.file_offset:x}",
                    "mirror": s.mirror,
                }
                for s in self.view.segments
            ],
        }
