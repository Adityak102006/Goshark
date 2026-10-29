from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal

MAX_MESSAGE_BYTES = 1 << 20
MAX_PACKET_BYTES = 65536


class EngineError(RuntimeError):
    pass


class EngineManager:
    def __init__(self) -> None:
        if sys.platform == "win32":
            config_path = os.environ.get("APPDATA") or os.fspath(Path.home() / "AppData" / "Roaming")
        elif sys.platform == "darwin":
            config_path = os.fspath(Path.home() / "Library" / "Application Support")
        else:
            config_path = os.environ.get("XDG_CONFIG_HOME") or os.fspath(Path.home() / ".config")
        self.socket_path = Path(config_path) / "goshark" / "engine.sock"
        self._lock = threading.RLock()
        self._process: subprocess.Popen[bytes] | None = None
        self._active: set[IpcTask] = set()
        self._capture: IpcTask | None = None
        self._next_id = 0

    def next_id(self) -> int:
        with self._lock:
            self._next_id += 1
            return self._next_id

    def submit(self, operation: str, values: dict[str, Any], token: Any = None) -> IpcTask:
        request_id = self.next_id()
        request = {"id": request_id, "type": "request", "operation": operation, **values}
        task = IpcTask(self, request, token)
        with self._lock:
            self._active.add(task)
            if operation == "start_capture":
                self._capture = task
        return task

    def stop_capture(self) -> None:
        with self._lock:
            task = self._capture
        if task is not None:
            task.stop()

    def release(self, task: IpcTask) -> None:
        with self._lock:
            self._active.discard(task)
            if self._capture is task:
                self._capture = None

    def connect(self) -> socket.socket:
        self._ensure_daemon()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(os.fspath(self.socket_path))
        except OSError as error:
            connection.close()
            raise EngineError(f"Could not connect to the goshark engine: {error}") from error
        return connection

    def _ensure_daemon(self) -> None:
        with self._lock:
            if self._probe():
                return
            if self._process is not None and self._process.poll() is None:
                process = self._process
            else:
                executable = self._find_executable()
                if executable is None:
                    raise EngineError("gosharkd was not found. Build it with `go build -o bin/gosharkd ./cmd/gosharkd` or set GOSHARK_ENGINE.")
                self.socket_path.parent.mkdir(parents=True, exist_ok=True)
                options: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
                if sys.platform == "win32":
                    options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                self._process = subprocess.Popen([os.fspath(executable), "--socket", os.fspath(self.socket_path)], **options)
                process = self._process
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self._probe():
                    return
                if process.poll() is not None:
                    raise EngineError(f"gosharkd exited with status {process.returncode}")
                time.sleep(0.05)
            raise EngineError("Timed out waiting for gosharkd to start")

    def _probe(self) -> bool:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(0.15)
        try:
            connection.connect(os.fspath(self.socket_path))
            return True
        except OSError:
            return False
        finally:
            connection.close()

    @staticmethod
    def _find_executable() -> Path | None:
        override = os.environ.get("GOSHARK_ENGINE")
        if override:
            candidate = Path(override).expanduser()
            if candidate.is_file():
                return candidate.resolve()
            return None
        executable_name = "gosharkd.exe" if sys.platform == "win32" else "gosharkd"
        bundled = Path(sys.executable).resolve().parent / executable_name
        if bundled.is_file():
            return bundled
        source_root = Path(__file__).resolve().parent.parent
        for relative in (Path("bin") / executable_name, Path("build") / executable_name, Path(executable_name)):
            candidate = source_root / relative
            if candidate.is_file():
                return candidate
        located = shutil.which(executable_name)
        return Path(located) if located else None

    def shutdown(self) -> None:
        with self._lock:
            active = tuple(self._active)
            process = self._process
        for task in active:
            task.stop()
        if process is not None and process.poll() is None:
            if sys.platform == "win32":
                process.terminate()
            else:
                process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)


class IpcTaskSignals(QObject):

    result = Signal(int, object, object)
    failed = Signal(int, object, str)
    finished = Signal(int, object)


class IpcTask(QRunnable):
    def __init__(self, manager: EngineManager, request: dict[str, Any], token: Any = None) -> None:
        super().__init__()
        self.manager = manager
        self.request = request
        self.token = token
        self.signals = IpcTaskSignals()
        self._socket_lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._stopped = False
        self.setAutoDelete(True)

    def stop(self) -> None:
        with self._socket_lock:
            self._stopped = True
            connection = self._socket
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def run(self) -> None:
        request_id = self.request["id"]
        operation = self.request["operation"]
        connection: socket.socket | None = None
        try:
            connection = self.manager.connect()
            with self._socket_lock:
                if self._stopped:
                    connection.close()
                    return
                self._socket = connection
            self._send(connection, self.request)
            while True:
                message = self._receive(connection)
                self.signals.result.emit(request_id, self.token, message)
                if message.get("type") in ("end", "error"):
                    if message.get("type") == "error":
                        raise EngineError(message.get("error", "Engine request failed"))
                    break
                if operation in ("list_interfaces", "packet_detail", "packet_bytes", "save_capture"):
                    break
        except (OSError, ValueError, json.JSONDecodeError, EngineError, struct.error) as error:
            with self._socket_lock:
                stopped = self._stopped
            if not stopped:
                self.signals.failed.emit(request_id, self.token, str(error))
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            self.manager.release(self)
            self.signals.finished.emit(request_id, self.token)

    @staticmethod
    def _send(connection: socket.socket, message: dict[str, Any]) -> None:
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if not payload or len(payload) > MAX_MESSAGE_BYTES:
            raise EngineError("IPC request exceeds the supported message size")
        connection.sendall(struct.pack(">I", len(payload)) + payload)

    @staticmethod
    def _receive(connection: socket.socket) -> dict[str, Any]:
        header = IpcTask._read_exact(connection, 4)
        size = struct.unpack(">I", header)[0]
        if size == 0 or size > MAX_MESSAGE_BYTES:
            raise EngineError(f"Invalid engine message length: {size}")
        message = json.loads(IpcTask._read_exact(connection, size))
        if not isinstance(message, dict) or not isinstance(message.get("type"), str):
            raise EngineError("Engine returned an invalid IPC message")
        return message

    @staticmethod
    def _read_exact(connection: socket.socket, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise EngineError("Engine closed the IPC connection")
            result.extend(chunk)
        return bytes(result)
