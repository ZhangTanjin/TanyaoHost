"""Single maps-snapshot parser → module/segment views (R5 D13/D14).

One truth for every address-inference consumer — list_modules,
address_resolve, resolve_module, and scan-preset building all derive from
MapsView, so they can never disagree about module extents, merge across
unrelated gaps, or fabricate ranges that are not in the snapshot.

Attribution rule (D9 continuity): an address belongs to whoever's mapping
contains it; mappings without a path or with '['-prefixed pseudo paths
([stack], [anon:*], [vdso], ...) are anonymous segments and never masquerade
as modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAP_READ = 1 << 0
MAP_WRITE = 1 << 1
MAP_EXEC = 1 << 2
MAP_PRIVATE = 1 << 3
MAP_SHARED = 1 << 4
MAP_ANONYMOUS = 1 << 5


def _is_anonymous_path(path: str) -> bool:
    return not path or path.startswith("[")


def _mark_mirrors(segments: list["Segment"]) -> None:
    """Flag whole-file mirror mappings — v2 (R7/D19).

    Within a page-aligned offset-0 group that contains an EXEC member, a
    non-EXEC member is a whole-file mirror ONLY when it DOMINATES the rest of
    the group in file space (size >= max other member size) — the integrity
    self-copy signature. Real co-resident loader PT_LOADs are strictly smaller
    than the exec image, so they must keep loader status:

    - lolm R5 layout: 202MB r--p off-0 beside a 192MB r-xp off-0 → mirror ✓
    - lolm R7 layout: ~58MB r--p off-0 beside the 192MB r-xp off-0 → REAL
      segment (the v1 rule mislabelled it and poisoned the load anchor by
      39.5MB — the tester's three-way base inconsistency)."""
    by_offset: dict[int, list[Segment]] = {}
    for s in segments:
        by_offset.setdefault(s.file_offset & ~0xFFF, []).append(s)
    for group in by_offset.values():
        if len(group) < 2 or not any(s.flags & MAP_EXEC for s in group):
            continue
        for s in group:
            if s.flags & MAP_EXEC:
                continue
            others_max = max((o.size for o in group if o is not s), default=0)
            s.mirror = s.size >= others_max


@dataclass(slots=True)
class Segment:
    start: int
    end: int
    file_offset: int
    flags: int
    path: str = ""
    mirror: bool = False

    @property
    def size(self) -> int:
        return self.end - self.start

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def flags_str(self) -> str:
        text = ""
        text += "r" if self.flags & 1 else "-"
        text += "w" if self.flags & 2 else "-"
        text += "x" if self.flags & 4 else "-"
        text += "p" if self.flags & 8 else ("s" if self.flags & 16 else "-")
        return text


@dataclass(slots=True)
class ModuleView:
    name: str
    path: str
    segments: list[Segment] = field(default_factory=list)

    @property
    def first_map(self) -> int:
        return self.segments[0].start

    @property
    def load_base(self) -> int:
        """First non-mirror segment — the loader-layout anchor consumers
        should prefer for base/rva arithmetic. Falls back to first_map when
        nothing is (or everything is) marked."""
        for s in self.segments:
            if not s.mirror:
                return s.start
        return self.first_map

    @property
    def max_end(self) -> int:
        return max(s.end for s in self.segments)

    def segment_index(self, addr: int) -> int | None:
        for i, s in enumerate(self.segments):
            if s.contains(addr):
                return i
        return None

    def file_offset_of(self, addr: int) -> int | None:
        i = self.segment_index(addr)
        if i is None:
            return None
        s = self.segments[i]
        return addr - s.start + s.file_offset

    def runtime_of(self, file_offset: int) -> int | None:
        """Per-mapping translation runtime = start + (F − file_offset) (D9)."""
        for s in self.segments:
            if s.file_offset <= file_offset < s.file_offset + s.size:
                return s.start + (file_offset - s.file_offset)
        return None


@dataclass(slots=True)
class MapsView:
    modules: dict[str, ModuleView]  # basename → view (first-seen path wins)
    anonymous: list[Segment]        # no path / '['-prefixed pseudo paths

    @classmethod
    def from_maps(cls, maps) -> "MapsView":
        modules: dict[str, ModuleView] = {}
        anonymous: list[Segment] = []
        for m in maps:
            seg = Segment(start=m.start, end=m.end, file_offset=m.file_offset,
                          flags=m.flags, path=m.path or "")
            if _is_anonymous_path(seg.path):
                anonymous.append(seg)
            else:
                name = seg.path.rstrip("/").split("/")[-1]
                view = modules.get(name)
                if view is None:
                    view = ModuleView(name=name, path=seg.path)
                    modules[name] = view
                view.segments.append(seg)
        for view in modules.values():
            view.segments.sort(key=lambda s: s.start)
            _mark_mirrors(view.segments)
        anonymous.sort(key=lambda s: s.start)
        return cls(modules=modules, anonymous=anonymous)

    def find(self, addr: int) -> tuple[ModuleView | None, int | None]:
        """→ (module_view, segment_index) on a module hit,
        (None, anonymous_index) on an anonymous hit,
        (None, None) when nothing in the snapshot contains the address."""
        for view in self.modules.values():
            i = view.segment_index(addr)
            if i is not None:
                return view, i
        for i, s in enumerate(self.anonymous):
            if s.contains(addr):
                return None, i
        return None, None

    def module_of(self, addr: int) -> ModuleView | None:
        view, _ = self.find(addr)
        return view
