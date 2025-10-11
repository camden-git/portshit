# PortShit

PortShit is a fast, opinionated network scanner that combines [zmap](https://zmap.io/) and [nmap](https://nmap.org/) to quickly scan large networks and capture RTSP camera screenshots. Results are stored in a structured SQLite database and scans can be paused and resumed.

## Key features

* Hybrid zmap -> nmap pipeline for ultra-fast discovery and high-fidelity service profiling
* Full nmap integration with customizable scripts and intensity levels
* Automatic RTSP detection + screenshot capture for Axis-style cameras
* Structured results in SQLite for easy querying and export (JSON/CSV)
* Resume interrupted scans and manage multiple sessions

## Prerequisites

* Rust (stable)
* nmap (in PATH)
* zmap (in PATH)
  * Required only for zmap discovery
* ffmpeg (in PATH)
  * Required only for camera capture
* SQLite (should be handled via sqlx)

> zmap requires root privileges to send packets; either run with `sudo` or skip zmap discovery and use pure nmap.

## Quick install

```bash
git clone https://github.com/camden-git/portshit.git
cd portshit
cargo build --release
```

Install OS packages if needed:

```bash
# macOS
brew install nmap zmap ffmpeg

# Ubuntu/Debian
sudo apt-get install nmap zmap ffmpeg
```

## Quickstart

Simple scan (env defaults or flags):

```bash
cargo run -- scan --target "192.168.1.0/24" --ports "1-1000"
```

zmap + two-pass (fast for large ranges; requires sudo):

```bash
sudo cargo run -- scan \
  --target "0.0.0.0/0" \
  --zmap-discovery --zmap-rate 50000 --two-pass --ports "80,443"
```

Resume a scan:

```bash
cargo run -- scan --resume-session <session-id> --database same-db-as-before.db
```

List sessions / show results / export:

```bash
cargo run -- list
cargo run -- show <session-id>
cargo run -- export <session-id> --format json --output results.json
```

View camera screenshots:

```bash
cargo run -- cameras <session-id>
```

## Environment / configuration

You can configure behavior via environment variables or CLI flags. Examples:

* `NMAP_TARGET_RANGE` — default `192.168.1.0/24`
* `NMAP_PORT_RANGE` — default `1-1000`
* `NMAP_DATABASE_PATH` — default `scan_results.db`
* `NMAP_USE_ZMAP_DISCOVERY` — `true`/`false`
* `NMAP_ZMAP_RATE` — packets/sec (e.g. `10000`)
* `NMAP_MAX_CONCURRENT_SCANS` — concurrency limit

A full list of the environment variables and CLI flags can be found in [`src/config.rs`](https://github.com/camden-git/portshit/blob/master/src/config.rs) and [`src/cli.rs`](https://github.com/camden-git/portshit/blob/master/src/cli.rs) respectively. 


## License

See [LICENSE](https://github.com/camden-git/mediasys/blob/master/LICENSE) for more information regarding the MIT license.