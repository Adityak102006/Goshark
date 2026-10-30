from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from PySide6.QtCore import QIODevice, QModelIndex, QSaveFile, Qt, QThreadPool, Signal
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence, QPixmap, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .branding import LOGO_PATH, brand_icon
from .engine import MAX_PACKET_BYTES, EngineManager
from .model import PacketTableModel

USER_ROLE = int(Qt.ItemDataRole.UserRole)

DARK_STYLE = """
QMainWindow, QWidget { background: #0b0d0e; color: #c9cecb; font: 13px 'Noto Sans', 'Segoe UI', sans-serif; }
QMenuBar, QMenu { background: #111415; color: #c9cecb; border: 1px solid #303635; }
QMenuBar::item:selected, QMenu::item:selected { background: #1e2323; color: #f0f2ef; }
QToolBar { background: #0b0d0e; border: 0; border-bottom: 1px solid #303635; spacing: 8px; padding: 4px 8px; }
QPushButton, QComboBox, QLineEdit { background: #181b1c; border: 1px solid #535b58; border-radius: 2px; min-height: 28px; padding: 2px 8px; color: #c9cecb; }
QPushButton:hover, QComboBox:hover { border-color: #c79550; color: #f0f2ef; }
QPushButton:pressed, QPushButton:checked { background: #44351f; border-color: #c79550; color: #f0f2ef; }
QPushButton:disabled { color: #69716d; border-color: #303635; }
QComboBox QAbstractItemView { background: #111415; selection-background-color: #1e2323; color: #f0f2ef; }
QLineEdit { background: #070808; selection-background-color: #44351f; font-family: 'Noto Sans Mono', Consolas, monospace; }
QLineEdit:focus { border-color: #c79550; }
QTableView, QTreeWidget, QPlainTextEdit, QTextEdit { background: #070808; alternate-background-color: #101312; border: 0; gridline-color: #303635; selection-background-color: #1e2323; selection-color: #f0f2ef; color: #c9cecb; }
QTableView { font-size: 12px; }
QTableView::item { border-bottom: 1px solid #1d2220; padding: 2px 5px; }
QHeaderView::section { background: #111415; color: #9fa6a2; border: 0; border-bottom: 1px solid #535b58; padding: 5px 7px; }
QTreeWidget { font-size: 12px; }
QTreeWidget::item { min-height: 21px; }
QStatusBar { background: #111415; border-top: 1px solid #535b58; color: #9fa6a2; }
QSplitter::handle { background: #303635; }
QScrollBar:vertical { background: #0b0d0e; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #303635; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #535b58; }
QScrollBar:horizontal { background: #0b0d0e; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #303635; min-width: 24px; }
QToolTip { background: #181b1c; color: #f0f2ef; border: 1px solid #535b58; padding: 4px; }
"""


class HexView(QPlainTextEdit):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(QFont("Noto Sans Mono", 10))
        self._data = b""

    def set_packet(self, data: bytes) -> None:
        self._data = data
        rows = []
        for offset in range(0, len(data), 16):
            section = data[offset : offset + 16]
            rows.append(f"{offset:04x}  " + " ".join(f"{byte:02x}" for byte in section))
        self.setPlainText("\n".join(rows))
        self.setExtraSelections([])

    def highlight_range(self, start: int, length: int) -> None:
        selections = []
        if length > 0 and start >= 0 and start < len(self._data):
            end = min(start + length, len(self._data))
            current = start
            while current < end:
                row = current // 16
                column = current % 16
                count = min(end - current, 16 - column)
                position = row * 54 + 6 + column * 3
                cursor = QTextCursor(self.document())
                cursor.setPosition(position)
                cursor.setPosition(position + count * 3 - 1, QTextCursor.MoveMode.KeepAnchor)
                selection = QTextEdit.ExtraSelection()
                selection.cursor = cursor
                selection.format.setBackground(QColor("#44351f"))
                selection.format.setForeground(QColor("#f0f2ef"))
                selections.append(selection)
                current += count
        self.setExtraSelections(selections)


class PacketDetails(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.heading = QLabel("Packet details")
        self.heading.setObjectName("paneHeading")
        layout.addWidget(self.heading)
        panes = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(1)
        panes.addWidget(self.tree)
        self.hex = HexView()
        panes.addWidget(self.hex)
        panes.setSizes([440, 300])
        layout.addWidget(panes, 1)
        self.tree.itemClicked.connect(self._field_selected)

    def set_details(self, packet_number: int, total_bytes: int, protocols: list[dict[str, Any]]) -> None:
        self.heading.setText(f"Packet {packet_number} · {total_bytes} bytes on wire")
        self.tree.clear()
        for protocol in protocols:
            root = QTreeWidgetItem([str(protocol.get("name", "Protocol"))])
            root.setData(0, USER_ROLE, None)
            self.tree.addTopLevelItem(root)
            for field in protocol.get("fields", []):
                item = QTreeWidgetItem([f"{field.get('name', '')}: {field.get('value', '')}"])
                item.setData(0, USER_ROLE, int(field.get("byte_start", 0)))
                item.setData(0, USER_ROLE + 1, int(field.get("byte_length", 0)))
                root.addChild(item)
            root.setExpanded(True)

    def set_packet_bytes(self, packet: bytes) -> None:
        self.hex.set_packet(packet)

    def _field_selected(self, item: QTreeWidgetItem, column: int) -> None:
        start = item.data(0, USER_ROLE)
        length = item.data(0, USER_ROLE + 1)
        if start is not None:
            self.hex.highlight_range(int(start), int(length or 0))


class FollowStreamWindow(QMainWindow):
    filter_out_requested = Signal(str)

    def __init__(self, metadata: dict[str, Any], segments: list[tuple[str, bytes]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.metadata = metadata
        self.segments = segments
        self.mode = "ASCII"
        self.setWindowTitle("Follow TCP Stream")
        self.resize(1000, 460)
        self.setMinimumSize(720, 340)
        self.setStyleSheet(DARK_STYLE)
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 6, 10, 6)
        toolbar_layout.setSpacing(8)
        self.mode_buttons: dict[str, QPushButton] = {}
        for mode in ("ASCII", "Hex", "Raw"):
            button = QPushButton(mode)
            button.setCheckable(True)
            button.setChecked(mode == "ASCII")
            button.clicked.connect(lambda checked=False, selected=mode: self._set_mode(selected))
            self.mode_buttons[mode] = button
            toolbar_layout.addWidget(button)
        toolbar_layout.addStretch(1)
        self.save_button = QPushButton("Save as…")
        self.save_button.clicked.connect(self._save_stream)
        toolbar_layout.addWidget(self.save_button)
        self.filter_button = QPushButton("Filter out this stream")
        self.filter_button.clicked.connect(self._filter_out)
        toolbar_layout.addWidget(self.filter_button)
        layout.addWidget(toolbar)
        self.summary = QLabel()
        self.summary.setContentsMargins(10, 7, 10, 7)
        self.summary.setStyleSheet("color: #9fa6a2; border-bottom: 1px solid #303635;")
        layout.addWidget(self.summary)
        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setFont(QFont("Noto Sans Mono", 10))
        self.view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.view, 1)
        self.setCentralWidget(central)
        self._update_summary()
        self._render()

    def _set_mode(self, mode: str) -> None:
        self.mode = mode
        for name, button in self.mode_buttons.items():
            button.setChecked(name == mode)
        self.view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap if mode == "Hex" else QTextEdit.LineWrapMode.WidgetWidth)
        self._render()

    def _update_summary(self) -> None:
        client = f"{self.metadata.get('client_address', '')}:{self.metadata.get('client_port', '')}"
        server = f"{self.metadata.get('server_address', '')}:{self.metadata.get('server_port', '')}"
        total = int(self.metadata.get("client_bytes", 0)) + int(self.metadata.get("server_bytes", 0))
        notices = []
        if self.metadata.get("client_gaps") or self.metadata.get("server_gaps"):
            notices.append("reassembly gaps detected")
        if self.metadata.get("truncated"):
            notices.append("stream truncated at the 8 MiB per-direction safety limit")
        suffix = " · " + " · ".join(notices) if notices else ""
        self.summary.setText(f"{client}  ↔  {server} · {total:,} bytes · {len(self.segments):,} segments{suffix}")

    def _render(self) -> None:
        self.view.clear()
        cursor = self.view.textCursor()
        client_format = QTextCharFormat()
        client_format.setForeground(QColor("#a5c8ad"))
        server_format = QTextCharFormat()
        server_format.setForeground(QColor("#d4b17a"))
        for direction, data in self.segments:
            label = "CLIENT →" if direction == "client" else "SERVER ←"
            current_format = client_format if direction == "client" else server_format
            cursor.insertText(label + "\n", current_format)
            if self.mode == "ASCII":
                cursor.insertText(self._printable(data) + "\n", current_format)
            elif self.mode == "Hex":
                for offset in range(0, len(data), 16):
                    chunk = data[offset : offset + 16]
                    cursor.insertText(f"{offset:08x}  " + " ".join(f"{byte:02x}" for byte in chunk) + "\n", current_format)
            else:
                cursor.insertText(f"{len(data):,} raw bytes\n{self._escaped_raw(data)}\n", current_format)
            cursor.insertText("\n")
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.view.setTextCursor(cursor)

    @staticmethod
    def _printable(data: bytes) -> str:
        text = data.decode("utf-8", errors="replace")
        return "".join(character if character.isprintable() or character in "\r\n\t" else "." for character in text)

    @staticmethod
    def _escaped_raw(data: bytes) -> str:
        pieces = []
        for value in data:
            if value == 0x5c:
                pieces.append("\\\\")
            elif value == 0x09:
                pieces.append("\\t")
            elif value == 0x0a:
                pieces.append("\\n")
            elif value == 0x0d:
                pieces.append("\\r")
            elif 0x20 <= value <= 0x7e:
                pieces.append(chr(value))
            else:
                pieces.append(f"\\x{value:02x}")
        return "".join(pieces)

    def _save_stream(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save TCP stream payload", "tcp-stream.bin", "Binary files (*.bin);;All files (*)")
        if not path:
            return
        output = QSaveFile(path)
        if not output.open(QIODevice.OpenModeFlag.WriteOnly):
            QMessageBox.warning(self, "Save stream", output.errorString())
            return
        content = b"".join(data for _, data in self.segments)
        if output.write(content) != len(content) or not output.commit():
            output.cancelWriting()
            QMessageBox.warning(self, "Save stream", output.errorString())
            return
        self.summary.setText(self.summary.text() + f" · Saved {Path(path).name}")

    def _filter_out(self) -> None:
        client = str(self.metadata.get("client_address", ""))
        server = str(self.metadata.get("server_address", ""))
        client_port = str(self.metadata.get("client_port", ""))
        server_port = str(self.metadata.get("server_port", ""))
        if not all((client, server, client_port, server_port)):
            QMessageBox.warning(self, "Filter stream", "The stream endpoint information is incomplete.")
            return
        network = "ipv6" if ":" in client else "ip"
        forward = f"({network}.src == {client} && tcp.srcport == {client_port} && {network}.dst == {server} && tcp.dstport == {server_port})"
        reverse = f"({network}.src == {server} && tcp.srcport == {server_port} && {network}.dst == {client} && tcp.dstport == {client_port})"
        self.filter_out_requested.emit(f"!{forward} && !{reverse}")


class MainWindow(QMainWindow):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("goshark")
        self.setWindowIcon(brand_icon())
        self.resize(1440, 790)
        self.setMinimumSize(980, 620)
        self.setStyleSheet(DARK_STYLE)
        self.manager = EngineManager()
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(6)
        self.model = PacketTableModel(self)
        self._request_meta: dict[int, dict[str, Any]] = {}
        self._current_path = ""
        self._capture_id = ""
        self._capture_active = False
        self._generation = 0
        self._selection_generation = 0
        self._packet_total = 0
        self._byte_data = bytearray()
        self._stream_windows: list[FollowStreamWindow] = []
        self._build_actions()
        self._build_ui()
        self._refresh_interfaces()
        self.statusBar().showMessage("Ready · local engine starts on demand")

    def _build_actions(self) -> None:
        self.open_action = QAction("Open capture…", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self._choose_capture)
        self.exit_action = QAction("Exit", self)
        self.exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        self.exit_action.triggered.connect(self.close)
        self.start_action = QAction("Start capture", self)
        self.start_action.setShortcut(QKeySequence("Ctrl+E"))
        self.start_action.triggered.connect(self._start_capture)
        self.stop_action = QAction("Stop capture", self)
        self.stop_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        self.stop_action.triggered.connect(self._stop_capture)
        self.stop_action.setEnabled(False)
        self.copy_action = QAction("Copy selected packet row", self)
        self.copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        self.copy_action.triggered.connect(self._copy_selected_row)
        self.focus_filter_action = QAction("Focus display filter", self)
        self.focus_filter_action.setShortcut(QKeySequence("Ctrl+/"))
        self.focus_filter_action.triggered.connect(self._focus_display_filter)
        self.about_action = QAction("About goshark", self)
        self.about_action.triggered.connect(self._show_about)
        self.follow_action = QAction("Follow TCP stream", self)
        self.follow_action.setEnabled(False)
        self.follow_action.setToolTip("Select a TCP packet in an offline capture")
        self.follow_action.triggered.connect(self._follow_stream)
        self.save_action = QAction("Save capture as…", self)
        self.save_action.setEnabled(False)
        self.save_action.setToolTip("Export the offline capture or completed live recording as PCAP")
        self.save_action.triggered.connect(self._save_capture)
        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.save_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        edit_menu = self.menuBar().addMenu("Edit")
        edit_menu.addAction(self.copy_action)
        view_menu = self.menuBar().addMenu("View")
        view_menu.addAction(self.focus_filter_action)
        capture_menu = self.menuBar().addMenu("Capture")
        capture_menu.addAction(self.start_action)
        capture_menu.addAction(self.stop_action)
        analyze_menu = self.menuBar().addMenu("Analyze")
        analyze_menu.addAction(self.follow_action)
        help_menu = self.menuBar().addMenu("Help")
        help_menu.addAction(self.about_action)

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 6, 10, 6)
        toolbar_layout.setSpacing(8)
        self.brand_logo = QLabel()
        self.brand_logo.setObjectName("brandLogo")
        self.brand_logo.setAccessibleName("goshark logo")
        self.brand_logo.setToolTip("goshark")
        self.brand_logo.setFixedSize(30, 30)
        self.brand_logo.setPixmap(QPixmap(str(LOGO_PATH)).scaled(
            30, 30, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        ))
        toolbar_layout.addWidget(self.brand_logo)
        self.brand_name = QLabel("goshark")
        self.brand_name.setObjectName("brandName")
        self.brand_name.setStyleSheet("font-size: 15px; font-weight: 600; letter-spacing: 0.5px; color: #f0f2ef; padding-right: 8px;")
        toolbar_layout.addWidget(self.brand_name)
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self._start_capture)
        toolbar_layout.addWidget(self.start_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop_capture)
        toolbar_layout.addWidget(self.stop_button)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh_interfaces)
        toolbar_layout.addWidget(self.refresh_button)
        toolbar_layout.addWidget(QLabel("Interface"))
        self.interface_box = QComboBox()
        self.interface_box.setMinimumWidth(210)
        toolbar_layout.addWidget(self.interface_box)
        toolbar_layout.addWidget(QLabel("Capture filter"))
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("tcp port 443")
        self.capture_filter.setMinimumWidth(190)
        toolbar_layout.addWidget(self.capture_filter)
        self.open_button = QPushButton("Open")
        self.open_button.clicked.connect(self._choose_capture)
        toolbar_layout.addWidget(self.open_button)
        toolbar_layout.addStretch(1)
        self.capture_label = QLabel("●  Capture stopped")
        self.capture_label.setStyleSheet("color: #9fa6a2; padding-right: 8px;")
        toolbar_layout.addWidget(self.capture_label)
        root.addWidget(toolbar)
        filter_row = QWidget()
        filter_layout = QHBoxLayout(filter_row)
        filter_layout.setContentsMargins(10, 5, 10, 6)
        filter_layout.setSpacing(8)
        filter_layout.addWidget(QLabel("Display filter"))
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("tcp.port == 443")
        self.display_filter.returnPressed.connect(self._apply_filter)
        filter_layout.addWidget(self.display_filter, 1)
        self.filter_status = QLabel("Ready")
        self.filter_status.setMinimumWidth(110)
        filter_layout.addWidget(self.filter_status)
        apply_button = QPushButton("Apply")
        apply_button.clicked.connect(self._apply_filter)
        filter_layout.addWidget(apply_button)
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self._clear_filter)
        filter_layout.addWidget(clear_button)
        root.addWidget(filter_row)
        workspace = QSplitter(Qt.Orientation.Horizontal)
        packet_pane = QWidget()
        packet_layout = QVBoxLayout(packet_pane)
        packet_layout.setContentsMargins(0, 0, 0, 0)
        packet_layout.setSpacing(0)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(25)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((56, 124, 110, 62, 120, 210, 58)):
            self.table.setColumnWidth(column, width)
        self.table.selectionModel().currentChanged.connect(self._packet_selected)
        packet_layout.addWidget(self.table, 1)
        self.packet_footer = QLabel("0 packets · 0 displayed · 0 dropped")
        self.packet_footer.setContentsMargins(10, 5, 10, 5)
        self.packet_footer.setStyleSheet("border-top: 1px solid #303635; color: #9fa6a2; font-size: 12px;")
        packet_layout.addWidget(self.packet_footer)
        workspace.addWidget(packet_pane)
        self.details = PacketDetails()
        workspace.addWidget(self.details)
        workspace.setSizes([790, 630])
        root.addWidget(workspace, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Ready")

    def _copy_selected_row(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        values = [str(self.model.data(self.model.index(row, column)) or "") for column in range(self.model.columnCount())]
        QApplication.clipboard().setText("\t".join(values))

    def _focus_display_filter(self) -> None:
        self.display_filter.setFocus()

    def _show_about(self) -> None:
        QMessageBox.about(self, "About goshark", "goshark\nNative PySide6 interface with a local Go packet engine.")

    def _submit(self, operation: str, values: dict[str, Any], meta: dict[str, Any]) -> int:
        task = self.manager.submit(operation, values, meta)
        request_id = task.request["id"]
        self._request_meta[request_id] = meta
        task.signals.result.connect(self._handle_result)
        task.signals.failed.connect(self._handle_error)
        task.signals.finished.connect(self._handle_finished)
        self.pool.start(task)
        return request_id

    def _refresh_interfaces(self) -> None:
        self.refresh_button.setEnabled(False)
        self._submit("list_interfaces", {}, {"kind": "interfaces"})

    def _choose_capture(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open capture", "", "Packet captures (*.pcap *.pcapng *.cap *.gz);;All files (*)")
        if path:
            self._open_capture(path)

    def _save_capture(self) -> None:
        live_source = not self._current_path and bool(self._capture_id)
        source = {"path": self._current_path} if self._current_path else {"capture_id": self._capture_id}
        if not source.get("path") and not source.get("capture_id"):
            self.statusBar().showMessage("No capture is available to export")
            return
        suggested = Path(self._current_path).with_suffix(".pcap").name if self._current_path else "goshark-live-capture.pcap"
        title = "Save completed live capture as PCAP" if live_source else "Save capture as"
        path, _ = QFileDialog.getSaveFileName(self, title, suggested, "PCAP capture (*.pcap);;All files (*)")
        if not path:
            return
        self._submit(
            "save_capture",
            {**source, "output_path": path, "display_filter": self.display_filter.text()},
            {"kind": "save", "path": path, "live": live_source},
        )
        message = "Exporting completed live capture" if live_source else "Exporting capture"
        self.statusBar().showMessage(f"{message} to {Path(path).name}…")

    def _open_capture(self, path: str) -> None:
        if self._capture_active:
            self._stop_capture()
        self._generation += 1
        self._selection_generation += 1
        self._current_path = str(Path(path).expanduser().resolve())
        self._capture_id = ""
        self.save_action.setEnabled(True)
        self.model.clear()
        self.details.tree.clear()
        self.details.hex.set_packet(b"")
        self._packet_total = 0
        self.follow_action.setEnabled(False)
        self.filter_status.setText("Applying…")
        self._submit("open_capture", {"path": self._current_path, "display_filter": self.display_filter.text()}, {"kind": "open", "generation": self._generation})
        self.statusBar().showMessage(f"Opening {Path(self._current_path).name}…")

    def _apply_filter(self) -> None:
        self.filter_status.setText("Checking…")
        if self._current_path:
            self._open_capture(self._current_path)
        else:
            self.filter_status.setText("Applied to the next capture")

    def _clear_filter(self) -> None:
        self.display_filter.clear()
        self._apply_filter()

    def _start_capture(self) -> None:
        if self._capture_active:
            return
        interface_name = self.interface_box.currentData()
        if not interface_name:
            QMessageBox.warning(self, "Capture", "Select an available capture interface first.")
            return
        self._generation += 1
        self._selection_generation += 1
        self._current_path = ""
        self._capture_id = ""
        self.save_action.setEnabled(False)
        self.model.clear()
        self.details.tree.clear()
        self.details.hex.set_packet(b"")
        self._packet_total = 0
        self._capture_active = True
        self.follow_action.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.capture_label.setText("●  Capturing")
        self.capture_label.setStyleSheet("color: #c79550; padding-right: 8px;")
        self._submit(
            "start_capture",
            {
                "interface_name": interface_name,
                "capture_filter": self.capture_filter.text(),
                "display_filter": self.display_filter.text(),
                "promiscuous": True,
            },
            {"kind": "live", "generation": self._generation},
        )
        self.statusBar().showMessage(f"Capturing on {interface_name}")

    def _stop_capture(self) -> None:
        if not self._capture_active:
            return
        self.manager.stop_capture()
        self.stop_button.setEnabled(False)
        self.stop_action.setEnabled(False)
        self.capture_label.setText("●  Stopping")
        self.statusBar().showMessage("Stopping capture…")

    def _packet_selected(self, current: QModelIndex, previous: QModelIndex) -> None:
        if not current.isValid():
            self.follow_action.setEnabled(False)
            self.details.heading.setText("Packet details")
            return
        packet_number = self.model.packet_number(current.row())
        if packet_number == 0:
            return
        row = self.model.packet_row(current.row())
        protocol = row.get("protocol", "").upper(); self.follow_action.setEnabled(bool(self._current_path) and protocol == "TCP")
        self._selection_generation += 1
        generation = self._selection_generation
        self._byte_data = bytearray()
        source = {"path": self._current_path} if self._current_path else {"capture_id": self._capture_id}
        if not source.get("path") and not source.get("capture_id"):
            self.details.heading.setText("Waiting for the live capture detail buffer")
            return
        token = {"kind": "detail", "generation": generation, "packet": packet_number, **source}
        self._submit("packet_detail", {**source, "packet_number": packet_number}, token)

    def _follow_stream(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        if not selected or not self._current_path:
            return
        packet_number = self.model.packet_number(selected[0].row())
        self._submit(
            "follow_tcp_stream",
            {"path": self._current_path, "packet_number": packet_number},
            {"kind": "stream", "generation": self._generation, "packet": packet_number},
        )
        self.statusBar().showMessage(f"Reassembling TCP stream for packet {packet_number}…")

    def _handle_result(self, request_id: int, token: Any, message: dict[str, Any]) -> None:
        if not isinstance(token, dict):
            return
        kind = token.get("kind")
        message_type = message.get("type")
        if message_type == "error":
            return
        if message_type == "response" and kind == "interfaces":
            self._show_interfaces(message.get("interfaces", []))
            return
        if message_type == "response" and kind == "save":
            count = int(message.get("displayed", 0))
            noun = "packet" if count == 1 else "packets"
            source = " from the live capture" if token.get("live") else ""
            truncated = " · live spool limit reached" if message.get("truncated") else ""
            self.statusBar().showMessage(f"Saved {count:,} {noun}{source} to {Path(token['path']).name} as PCAP{truncated}")
            return
        if message_type == "response" and kind == "live":
            if token.get("generation") == self._generation:
                self._capture_id = str(message.get("capture_id", ""))
                self.save_action.setEnabled(False)
            return
        if message_type == "batch" and kind in ("open", "live"):
            if token.get("generation") != self._generation:
                return
            self.model.append_batch(message.get("frames", []))
            self._packet_total = int(message.get("captured", self._packet_total))
            self._update_counts(int(message.get("displayed", self.model.rowCount())), int(message.get("dropped", 0)))
            if self.model.rowCount() and not self.table.selectionModel().hasSelection() and not self._capture_active:
                self.table.selectRow(0)
            return
        if message_type == "end" and kind in ("open", "live"):
            self._packet_total = int(message.get("captured", self._packet_total))
            self._update_counts(int(message.get("displayed", self.model.rowCount())), int(message.get("dropped", 0)))
            if kind == "open":
                self.filter_status.setText("Applied")
                self.statusBar().showMessage(f"Loaded {Path(self._current_path).name}")
            else:
                self.statusBar().showMessage("Capture stopped")
            return
        if message_type == "response" and kind == "detail":
            if token.get("generation") != self._selection_generation:
                return
            total = int(message.get("total_bytes", 0))
            self.details.set_details(token["packet"], total, message.get("protocols", []))
            self._submit(
                "packet_bytes",
                {**{key: token[key] for key in ("path", "capture_id") if key in token}, "packet_number": token["packet"], "byte_offset": 0, "byte_length": min(MAX_PACKET_BYTES, total)},
                {"kind": "bytes", "generation": token["generation"], "packet": token["packet"], "total": total},
            )
            return
        if message_type == "response" and kind == "bytes":
            if token.get("generation") != self._selection_generation:
                return
            data = message.get("data", "")
            if isinstance(data, str):
                self._byte_data.extend(base64.b64decode(data, validate=True))
            if message.get("more") and len(self._byte_data) < token["total"]:
                start = len(self._byte_data)
                self._submit(
                    "packet_bytes",
                    {
                        **{key: token[key] for key in ("path", "capture_id") if key in token},
                        "packet_number": token["packet"],
                        "byte_offset": start,
                        "byte_length": min(MAX_PACKET_BYTES, token["total"] - start),
                    },
                    token,
                )
            else:
                self.details.set_packet_bytes(bytes(self._byte_data))
            return
        if kind == "stream" and message_type == "response":
            if token.get("generation") != self._generation:
                return
            token["metadata"] = message
            token["segments"] = []
            if message.get("truncated"):
                self.statusBar().showMessage("Stream reached the 8 MiB per-direction display limit")
            return
        if kind == "stream" and message_type == "batch":
            if token.get("generation") != self._generation:
                return
            data = message.get("data", "")
            if isinstance(data, str):
                token.setdefault("segments", []).append((str(message.get("stream_direction", "")), base64.b64decode(data, validate=True)))
            return
        if kind == "stream" and message_type == "end":
            if token.get("generation") != self._generation:
                return
            metadata = token.get("metadata")
            segments = token.get("segments")
            if metadata is None or segments is None:
                return
            stream_window = FollowStreamWindow(metadata, segments, self)
            stream_window.filter_out_requested.connect(self._apply_stream_filter)
            self._stream_windows.append(stream_window)
            stream_window.show()
            self.statusBar().showMessage(f"Reassembled TCP stream for packet {token['packet']}")

    def _apply_stream_filter(self, expression: str) -> None:
        current = self.display_filter.text().strip()
        self.display_filter.setText(f"({current}) && ({expression})" if current else expression)
        self._apply_filter()

    def _show_interfaces(self, interfaces: list[dict[str, Any]]) -> None:
        selected = self.interface_box.currentData()
        self.interface_box.clear()
        for interface in interfaces:
            name = str(interface.get("name", ""))
            description = str(interface.get("description", ""))
            label = f"{name} · {description}" if description and description != name else name
            self.interface_box.addItem(label, name)
        if selected:
            index = self.interface_box.findData(selected)
            if index >= 0:
                self.interface_box.setCurrentIndex(index)
        self.refresh_button.setEnabled(True)
        if interfaces:
            self.statusBar().showMessage(f"{len(interfaces)} capture interfaces available")
        else:
            self.statusBar().showMessage("No capture interfaces were returned")

    def _update_counts(self, displayed: int, dropped: int) -> None:
        self.packet_footer.setText(f"{self._packet_total:,} packets · {displayed:,} displayed · {dropped:,} dropped")

    def _handle_error(self, request_id: int, token: Any, message: str) -> None:
        if not isinstance(token, dict):
            return
        kind = token.get("kind")
        if kind == "interfaces":
            self.refresh_button.setEnabled(True)
        if kind == "live":
            self._capture_active = False
            self._capture_controls(False)
            self.save_action.setEnabled(bool(self._capture_id))
        if kind == "open":
            self.filter_status.setText("Invalid or unavailable")
        self.statusBar().showMessage(message)
        if kind not in ("bytes", "detail", "interfaces"):
            QMessageBox.warning(self, "goshark engine", message)

    def _handle_finished(self, request_id: int, token: Any) -> None:
        self._request_meta.pop(request_id, None)
        if isinstance(token, dict) and token.get("kind") == "live":
            self._capture_active = False
            self._capture_controls(False)
            self.save_action.setEnabled(bool(self._capture_id))
            if self.capture_label.text().endswith("Stopping") or self.capture_label.text().endswith("Capturing"):
                self.capture_label.setText("●  Capture stopped")
                self.capture_label.setStyleSheet("color: #9fa6a2; padding-right: 8px;")

    def _capture_controls(self, active: bool) -> None:
        self.start_button.setEnabled(not active)
        self.stop_button.setEnabled(active)
        self.start_action.setEnabled(not active)
        self.stop_action.setEnabled(active)

    def closeEvent(self, event: Any) -> None:
        self.manager.shutdown()
        self.model.close()
        event.accept()


def set_dark_application_style(application: QApplication) -> None:
    application.setStyleSheet(DARK_STYLE)
