import os
import socket
import threading
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from goshark.branding import LOGO_PATH, brand_icon
from goshark.engine import IpcTask
from goshark.model import PacketTableModel
from goshark.ui import FollowStreamWindow, HexView, MainWindow


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_packet_model_uses_a_bounded_page_cache(self):
        model = PacketTableModel()
        rows = [
            {
                "number": number,
                "timestamp": f"2026-10-28T12:00:{number % 60:02d}Z",
                "source": "192.0.2.1",
                "source_port": "12345",
                "destination": "198.51.100.2",
                "info": "TCP 12345 → 443 [ACK]",
                "length": 66,
            }
            for number in range(1, 513)
        ]
        model.append_batch(rows[:128])
        model.append_batch(rows[128:])
        self.assertEqual(model.rowCount(), 512)
        self.assertEqual(model.data(model.index(257, 0)), "258")
        self.assertEqual(model.data(model.index(257, 5)), "TCP 12345 → 443 [ACK]")
        self.assertEqual(model.packet_number(511), 512)
        self.assertLessEqual(len(model._cache), model._cache_limit)
        self.assertGreater(model.backing_store_size(), 0)
        model.close()

    def test_hex_field_highlight_maps_byte_ranges(self):
        view = HexView()
        view.set_packet(bytes(range(64)))
        view.highlight_range(15, 3)
        selections = view.extraSelections()
        self.assertEqual(len(selections), 2)
        self.assertEqual(selections[0].cursor.selectedText(), "0f")
        self.assertEqual(selections[1].cursor.selectedText(), "10 11")

    def test_save_capture_ipc_task_stops_after_single_response(self):
        client, server = socket.socketpair()
        received = []
        failed = []
        class Manager:
            def connect(self):
                return client
            def release(self, task):
                return None
        def reply():
            request = IpcTask._receive(server)
            IpcTask._send(server, {"id": request["id"], "type": "response", "format": "pcap", "displayed": 1})
            server.close()
        thread = threading.Thread(target=reply)
        thread.start()
        task = IpcTask(Manager(), {"id": 12, "type": "request", "operation": "save_capture"})
        task.signals.result.connect(lambda request_id, token, message: received.append(message))
        task.signals.failed.connect(lambda request_id, token, message: failed.append(message))
        task.run()
        thread.join(timeout=2)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["displayed"], 1)
        self.assertEqual(failed, [])
        server.close()

    def test_ipc_frame_round_trip(self):
        left, right = socket.socketpair()
        try:
            IpcTask._send(left, {"id": 9, "type": "request", "operation": "list_interfaces"})
            decoded = IpcTask._receive(right)
            self.assertEqual(decoded["id"], 9)
            self.assertEqual(decoded["operation"], "list_interfaces")
        finally:
            left.close()
            right.close()

    def test_main_window_is_native_and_matches_the_approved_menus(self):
        window = MainWindow()
        menus = [action.text() for action in window.menuBar().actions()]
        self.assertEqual(menus, ["File", "Edit", "View", "Capture", "Analyze", "Help"])
        self.assertIsNotNone(window.table.model())
        self.assertTrue(LOGO_PATH.is_file())
        self.assertFalse(brand_icon().isNull())
        self.assertFalse(window.windowIcon().isNull())
        self.assertEqual(window.brand_name.text(), "goshark")
        self.assertFalse(window.follow_action.isEnabled())
        self.assertFalse(window.save_action.isEnabled())
        window.close()
        self.application.processEvents()

    def test_follow_stream_window_switches_views_and_builds_filter(self):
        metadata = {
            "client_address": "192.0.2.1",
            "server_address": "198.51.100.2",
            "client_port": "12345",
            "server_port": "443",
            "client_bytes": 4,
            "server_bytes": 5,
            "client_gaps": 0,
            "server_gaps": 0,
            "truncated": False,
        }
        window = FollowStreamWindow(metadata, [("client", b"GET \r\n\x00"), ("server", b"HTTP/")])
        self.assertIn("192.0.2.1:12345", window.summary.text())
        window._set_mode("Hex")
        self.assertIn("47 45 54 20", window.view.toPlainText())
        window._set_mode("Raw")
        self.assertIn(r"GET \r\n\x00", window.view.toPlainText())
        expressions = []
        window.filter_out_requested.connect(expressions.append)
        window._filter_out()
        self.assertEqual(len(expressions), 1)
        self.assertIn("tcp.srcport == 12345", expressions[0])
        window.close()

    def test_open_capture_picker_includes_compressed_capture_files(self):
        window = MainWindow()
        opened = []
        window._open_capture = opened.append
        with patch("goshark.ui.QFileDialog.getOpenFileName", return_value=("/captures/sample.pcapng.gz", "")) as dialog:
            window._choose_capture()
        self.assertIn("*.gz", dialog.call_args.args[3])
        self.assertEqual(opened, ["/captures/sample.pcapng.gz"])
        window.close()
        self.application.processEvents()

    def test_save_capture_action_submits_current_source_and_display_filter(self):
        window = MainWindow()
        submitted = []
        window._submit = lambda operation, values, meta: submitted.append((operation, values, meta)) or len(submitted)
        window._current_path = "/captures/source.pcapng"
        window.display_filter.setText("tcp.port == 80")
        with patch("goshark.ui.QFileDialog.getSaveFileName", return_value=("/captures/filtered.pcap", "PCAP capture (*.pcap)")):
            window._save_capture()
        self.assertEqual(submitted[0][0], "save_capture")
        self.assertEqual(submitted[0][1], {
            "path": "/captures/source.pcapng",
            "output_path": "/captures/filtered.pcap",
            "display_filter": "tcp.port == 80",
        })
        window._handle_result(1, submitted[0][2], {"type": "response", "displayed": 3})
        self.assertIn("Saved 3 packets", window.statusBar().currentMessage())
        window.close()
        self.application.processEvents()

    def test_live_export_uses_completed_capture_snapshot(self):
        window = MainWindow()
        submitted = []
        window._submit = lambda operation, values, meta: submitted.append((operation, values, meta)) or len(submitted)
        window._capture_id = "session-1"
        with patch("goshark.ui.QFileDialog.getSaveFileName", return_value=("/captures/recent.pcap", "PCAP")) as dialog:
            window._save_capture()
        self.assertEqual(dialog.call_args.args[1], "Save completed live capture as PCAP")
        self.assertEqual(submitted[0][1]["capture_id"], "session-1")
        self.assertNotIn("path", submitted[0][1])
        self.assertTrue(submitted[0][2]["live"])
        window._handle_result(1, submitted[0][2], {"type": "response", "displayed": 2, "truncated": True})
        self.assertIn("2 packets from the live capture", window.statusBar().currentMessage())
        self.assertIn("live spool limit reached", window.statusBar().currentMessage())
        window.close()
        self.application.processEvents()

    def test_live_capture_save_becomes_available_only_after_stop(self):
        window = MainWindow()
        window._capture_active = True
        window.save_action.setEnabled(False)
        token = {"kind": "live", "generation": window._generation}
        window._handle_result(1, token, {"type": "response", "capture_id": "session-1"})
        self.assertFalse(window.save_action.isEnabled())
        window._handle_finished(1, token)
        self.assertTrue(window.save_action.isEnabled())
        window.close()
        self.application.processEvents()

    def test_live_packet_selection_uses_capture_session_for_details(self):
        window = MainWindow()
        submitted = []
        window._submit = lambda operation, values, meta: submitted.append((operation, values, meta)) or len(submitted)
        window._capture_id = "session-1"
        window.model.append_batch([{
            "number": 7,
            "timestamp": "2026-10-28T12:00:00Z",
            "source": "192.0.2.1",
            "source_port": "12345",
            "destination": "198.51.100.2",
            "protocol": "TCP",
            "info": "TCP 12345 → 443",
            "length": 66,
        }])
        window.table.selectRow(0)
        self.assertEqual(submitted[0][0], "packet_detail")
        self.assertEqual(submitted[0][1], {"capture_id": "session-1", "packet_number": 7})
        window._handle_result(1, submitted[0][2], {"type": "response", "total_bytes": 66, "protocols": []})
        self.assertEqual(submitted[1][0], "packet_bytes")
        self.assertEqual(submitted[1][1]["capture_id"], "session-1")
        self.assertNotIn("path", submitted[1][1])
        window.close()
        self.application.processEvents()

    def test_table_header_names_match_mockup(self):
        model = PacketTableModel()
        actual = [
            model.headerData(column, Qt.Orientation.Horizontal)
            for column in range(model.columnCount())
        ]
        self.assertEqual(actual, ["No.", "Time", "Source", "Src Port", "Destination", "Info", "Length"])
        model.close()


if __name__ == "__main__":
    unittest.main()
