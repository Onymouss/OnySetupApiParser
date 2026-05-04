from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image


def ensure_logo_icon(project_root: Path) -> Path:
    assets = project_root / "assets"
    png_path = assets / "onyforensics-logo.png"
    ico_path = assets / "onyforensics-logo.ico"

    if not png_path.exists():
        raise FileNotFoundError(f"Logo PNG not found: {png_path}")

    img = Image.open(png_path).convert("RGBA")
    img.save(
        ico_path,
        format="ICO",
        sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
    )
    return ico_path


def build(project_root: Path, ico_path: Path) -> None:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "OnyForensics-SetupAPI",
        "--icon",
        str(ico_path),
        str(project_root / "Parser.py"),
    ]
    subprocess.run(cmd, cwd=project_root, check=True)


def main() -> None:
    project_root = Path(__file__).resolve().parent
    ico_path = ensure_logo_icon(project_root)
    build(project_root, ico_path)
    exe_path = project_root / "dist" / "OnyForensics-SetupAPI.exe"
    print(f"Build complete: {exe_path}")


if __name__ == "__main__":
    main()
