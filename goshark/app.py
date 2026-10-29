from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication

from . import __version__
from .branding import brand_icon
from .ui import MainWindow, set_dark_application_style


def main() -> int:
    QCoreApplication.setOrganizationName("goshark")
    QCoreApplication.setApplicationName("goshark")
    QCoreApplication.setApplicationVersion(__version__)
    application = QApplication(sys.argv)
    application.setStyle("Fusion")
    application.setWindowIcon(brand_icon())
    set_dark_application_style(application)
    window = MainWindow()
    window.show()
    if len(sys.argv) > 1:
        window._open_capture(sys.argv[1])
    return application.exec()
