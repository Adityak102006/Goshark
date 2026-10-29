from __future__ import annotations

import array
import json
import os
import tempfile
from collections import OrderedDict
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor


class PacketTableModel(QAbstractTableModel):
    columns = ("No.", "Time", "Source", "Src Port", "Destination", "Info", "Length")

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._file = tempfile.TemporaryFile(mode="w+b")
        self._offsets = array.array("Q")
        self._cache: OrderedDict[int, tuple[dict[str, Any], ...]] = OrderedDict()
        self._page_size = 128
        self._cache_limit = 16

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._offsets)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.columns):
            return self.columns[section]
        if orientation == Qt.Orientation.Vertical and 0 <= section < len(self._offsets):
            return str(section + 1)
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.BackgroundRole:
            protocol = str(self._row(index.row()).get("protocol", "")).lower()
            background = {"tcp": "#171b1a", "dns": "#1b1c17", "tls": "#17191d"}.get(protocol)
            return QBrush(QColor(background)) if background else None
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 3, 6):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        row = self._row(index.row())
        key = ("number", "timestamp", "source", "source_port", "destination", "info", "length")[index.column()]
        value = row.get(key, "")
        if key == "length":
            return str(value)
        if key == "timestamp":
            timestamp = str(value)
            return timestamp.split("T", 1)[-1].removesuffix("Z")
        return str(value)

    def append_batch(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        start = len(self._offsets)
        end = start + len(rows) - 1
        self.beginInsertRows(QModelIndex(), start, end)
        try:
            for row in rows:
                encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                self._offsets.append(self._file.tell())
                self._file.write(encoded)
        finally:
            self.endInsertRows()
        self._file.flush()
        self._cache.clear()

    def clear(self) -> None:
        self.beginResetModel()
        self._file.close()
        self._file = tempfile.TemporaryFile(mode="w+b")
        self._offsets = array.array("Q")
        self._cache.clear()
        self.endResetModel()

    def packet_number(self, row: int) -> int:
        if row < 0 or row >= len(self._offsets):
            return 0
        return int(self._row(row).get("number", row + 1))

    def packet_row(self, row: int) -> dict[str, Any]:
        return dict(self._row(row))

    def _row(self, row: int) -> dict[str, Any]:
        if row < 0 or row >= len(self._offsets):
            return {}
        page = row // self._page_size
        records = self._cache.get(page)
        if records is None:
            first = page * self._page_size
            last = min(first + self._page_size, len(self._offsets))
            self._file.seek(self._offsets[first])
            loaded = []
            for _ in range(last - first):
                line = self._file.readline()
                if not line:
                    break
                loaded.append(json.loads(line))
            records = tuple(loaded)
            self._cache[page] = records
            while len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)
        else:
            self._cache.move_to_end(page)
        offset = row - page * self._page_size
        return records[offset] if offset < len(records) else {}

    def close(self) -> None:
        self._file.close()

    def backing_store_size(self) -> int:
        return os.fstat(self._file.fileno()).st_size
