from pathlib import Path

from PySide6.QtGui import QIcon


LOGO_PATH = Path(__file__).resolve().parent / "assets" / "goshark-logo.png"


def brand_icon() -> QIcon:
    return QIcon(str(LOGO_PATH))
