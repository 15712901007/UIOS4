"""Shared helpers for adaptive LAN/WAN physical-interface handling."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Sequence


_NIC_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:veth\d+|eth\d+|enp\d+s\d+(?:f\d+)?|ens\d+(?:f\d+)?|eno\d+|em\d+)"
    r"(?![A-Za-z0-9_])",
    re.IGNORECASE,
)


def natural_interface_key(name: str) -> tuple:
    """Sort interface names by text and numeric components."""
    return tuple(
        int(part) if part.isdigit() else part.casefold()
        for part in re.split(r"(\d+)", str(name or ""))
    )


def split_interface_names(value: Any) -> List[str]:
    """Split a DB/UI interface list while preserving exact kernel names."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        parts: Iterable[Any] = value
    else:
        parts = re.split(r"[,\s]+", str(value))
    result: List[str] = []
    seen = set()
    for part in parts:
        name = str(part or "").strip()
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            result.append(name)
    return result


def extract_physical_nic_names(text: str) -> List[str]:
    """Extract exact eth/veth and predictable-name NIC tokens from UI text."""
    found: Dict[str, str] = {}
    for match in _NIC_TOKEN_RE.finditer(str(text or "")):
        name = match.group(0)
        found.setdefault(name.casefold(), name)
    return sorted(found.values(), key=natural_interface_key)


def choose_reassignable_nics(
    bound_names: Sequence[str],
    link_state: Dict[str, Dict[str, Any]],
    *,
    count: int = 1,
) -> List[str]:
    """Choose LAN NICs to release, always retaining one bound NIC.

    Carrier-down links are preferred. Active links and the first bound link are
    retained whenever possible so the operation is compatible with both
    physical ``eth*`` appliances and virtual ``veth*`` devices.
    """
    names = split_interface_names(bound_names)
    indexed = {name.casefold(): index for index, name in enumerate(names)}

    def is_active(name: str) -> bool:
        state = link_state.get(name) or link_state.get(name.casefold()) or {}
        carrier = str(state.get("carrier", "")).strip()
        operstate = str(state.get("state", "")).upper()
        flags = {str(item).upper() for item in state.get("flags", [])}
        return carrier == "1" or operstate == "UP" or "LOWER_UP" in flags

    # The first bound member is commonly the firmware-protected management
    # port even when carrier is down. Also retain one live member when that is
    # a different NIC, otherwise releasing inactive links can strand LAN1.
    protected = {names[0].casefold()} if names else set()
    active_names = [name for name in names if is_active(name)]
    if active_names:
        protected.add(active_names[0].casefold())

    candidates = [name for name in names if name.casefold() not in protected]
    wanted = min(max(0, int(count)), len(candidates))
    if wanted == 0:
        return []

    def score(name: str) -> tuple:
        # Prefer inactive links; among ties, release later-numbered links first.
        return (1 if is_active(name) else 0, -indexed[name.casefold()])

    return sorted(candidates, key=score)[:wanted]


def interface_rows_equal(
    expected: Dict[str, Any],
    actual: Dict[str, Any],
    *,
    ignored_fields: Sequence[str] = (),
) -> bool:
    """Compare a configuration row without hiding missing or extra fields."""
    ignored = set(ignored_fields)
    keys = (set(expected or {}) | set(actual or {})) - ignored
    return all(str((expected or {}).get(key, "")) == str((actual or {}).get(key, "")) for key in keys)
