from __future__ import annotations

import sys

from PyQt6.QtGui     import QColor, QPalette
from PyQt6.QtWidgets import QApplication

from core.config    import C, QSS
from ui.main_window import MainWin


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Oxsium Framework")
    app.setStyleSheet(QSS)

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,          QColor(C.BASE))
    pal.setColor(QPalette.ColorRole.WindowText,      QColor(C.T0))
    pal.setColor(QPalette.ColorRole.Base,            QColor(C.SURF0))
    pal.setColor(QPalette.ColorRole.AlternateBase,   QColor(C.SURF1))
    pal.setColor(QPalette.ColorRole.Text,            QColor(C.T0))
    pal.setColor(QPalette.ColorRole.Button,          QColor(C.SURF1))
    pal.setColor(QPalette.ColorRole.ButtonText,      QColor(C.T0))
    pal.setColor(QPalette.ColorRole.Highlight,       QColor(C.BLUE_B))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(C.T0))
    app.setPalette(pal)

    w = MainWin()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()