# goshark

A native Qt Widgets packet analyzer with a Go capture engine. The desktop client uses PySide6; it does not embed a browser or WebView. The interface follows the approved matte-black native desktop design.

## Build and run

Supported platform for now: Linux. Requirements: Go 1.27.3 or newer, Python 3.10 through 3.15, PySide6 6.12.0, and libpcap development/runtime files for live capture. Live capture may require elevated capture permissions. Windows and macOS are not currently supported or verified.

```sh
mkdir -p bin
go test ./...
go build -o bin/gosharkd ./cmd/gosharkd
python -m pip install -e .
goshark
```

To open a capture from the command line:

```sh
goshark testdata/http.pcap
```

The GUI starts `gosharkd` on demand. Set `GOSHARK_ENGINE` to the engine executable's full path if it is not in `bin/`, next to the application, or on `PATH`.

## Command-line tools

Build the native packet CLI and editcap-like utility:

```sh
mkdir -p bin
go build -o bin/tgoshark ./cmd/tgoshark
go build -o bin/goedit ./cmd/goedit
```

`tgoshark --interfaces` lists capture interfaces. Read and display-filter a file with:

```sh
bin/tgoshark --read testdata/http.pcap --display-filter 'tcp.port == 80' --verbose --hex
```

For live capture, select an interface with `--interface NAME`; `--capture-filter` uses the installed libpcap filter compiler, while `--display-filter` uses goshark's filter language. `--limit`, `--snaplen`, `--promiscuous`, and `--output` control capture. `--output` writes every packet read to classic PCAP; the display filter controls which packets are printed, not which packets are written. Run either binary with `--help` for its exact option list.

`goedit` applies editcap-like selection and rewrite operations. For example, keep the first packet and shift its timestamp by one second:

```sh
bin/goedit -keep-ranges 1 -time-shift 1s testdata/http.pcap /tmp/edited.pcap
```

It also accepts `-start-time`, `-end-time`, `-dedupe`, `-snaplen`, and `-split-count`. Output is classic PCAP; verify destination paths before running because input and output must be separate.

## Tests

```sh
go test ./...
go test -race ./...
go vet ./...
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
```

## Current implementation status

The native Qt UI can open offline captures, stream display-filtered packet rows, enumerate interfaces, show packet protocol trees and selected byte ranges, retrieve packet bytes, follow offline TCP streams in ASCII/Hex/Raw modes, and save stream payloads. Live capture start/stop is connected to the engine when the OS capture backend and permissions allow it. Recent live packets have on-demand detail/byte lookup from a bounded in-memory cache (up to 4 sessions; 64 MiB or 4,096 packets per session). Each session also records packets to a private temporary PCAP spool capped at 1 GiB; the spool is removed on orderly engine shutdown or session eviction (a forced process kill may leave an orphaned private temporary directory).

The File → Save Capture action exports packets matching the current display filter as classic PCAP. Offline PCAP, PCAPNG, and gzip-compressed captures (including `.pcapng.gz`) are converted to PCAP. After a live capture stops, export uses the full recorded session up to the 1 GiB spool limit; when that limit is reached, export reports that the recording was truncated. Export is written atomically. Classic PCAP output has one link type and microsecond timestamp precision; PCAPNG interface metadata/options are not preserved.

Current field-level dissection includes Ethernet, ARP, IPv4/IPv6, TCP, UDP, DNS header metadata, basic HTTP request/response start lines and selected headers, TLS record type/version/length, and RadioTap/802.11 management beacon and information-element fields. This is not full Wireshark protocol coverage. TLS/HTTPS application data remains encrypted; no TLS decryption, certificate analysis, or full HTTP message/body reassembly is implemented. TCP stream reassembly is bounded and should be treated as best-effort for incomplete captures; gaps and truncation are shown in the UI.

Offline integration was exercised with `testdata/http.pcap`; application-protocol and export tests use synthetic packet records plus that fixture. Live packet detail is tested through the bounded in-memory cache, and full live-recording export is tested through the disk spool. Actual live packet capture has not succeeded in this environment because capture permissions are unavailable. A GitHub Actions workflow is defined at `.github/workflows/ci.yml` and currently targets Linux only, running Go checks/build plus Qt tests. Hosted CI has not run. Installers and a genuine native desktop screenshot remain unverified. Linux Qt offscreen renders are retained at `screenshots/linux-offscreen-main.png` and `screenshots/linux-offscreen-follow-tcp.png`; they are not native desktop-window screenshots.
