import importlib
import os
import pkgutil


def _discovered_modules() -> list[str]:
    return sorted(
        module.name
        for module in pkgutil.iter_modules(__path__)
        if not module.name.startswith("_")
    )


def _selected_modules() -> list[str]:
    discovered = _discovered_modules()
    only = os.environ.get("LIVE_SMOKE_ONLY_MODULES", "").strip()
    if not only:
        return discovered
    wanted = {name.strip() for name in only.split(",") if name.strip()}
    unknown = wanted - set(discovered)
    if unknown:
        raise ImportError(f"Unknown live-smoke scenario modules: {sorted(unknown)}")
    return [name for name in discovered if name in wanted]


LOADED_MODULES: tuple[str, ...] = tuple(_selected_modules())

for _name in LOADED_MODULES:
    importlib.import_module(f"{__name__}.{_name}")
