import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "examples" / "advanced_app" / "app"
STACK_DIR = Path(__file__).resolve().parent / "stack"
DEST = STACK_DIR / "app"


def copy_example_app() -> None:
    if not SOURCE.is_dir():
        raise RuntimeError(f"examples/advanced_app/app not found under {REPO_ROOT}")
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(SOURCE, DEST)


def main() -> int:
    copy_example_app()
    print(f"copied examples/advanced_app/app -> {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
