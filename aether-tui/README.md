# aether-tui

A small read-only status screen for [Aether](https://github.com/CluvexStudio/Aether) on Termux.

It starts a single `aether` process that serves two SOCKS5 proxies:

| Port | Exit |
| --- | --- |
| `127.0.0.1:10889` | WARP over MASQUE (HTTP/3) |
| `127.0.0.1:10890` | psiphon, carried inside that WARP tunnel |

The command it runs:

```
aether --masque --h3 --bind 127.0.0.1:10889 --psiphon --psiphon-bind 127.0.0.1:10890 --config ~/.aether-tui/aether.toml
```

The screen shows:

- aether's current state
- traffic totals and rates
- for each port, whether it really passes traffic (it fetches `https://www.cloudflare.com/cdn-cgi/trace` through the proxy), plus the exit IP, location, Cloudflare colo, `warp=` value and round-trip time
- the tail of aether's log

## Requirements

- Python 3 (`pkg install python`). It uses only the standard library.
- aether, installed with its Termux installer, which also installs `psiphon-tunnel-core` into `$PREFIX/bin/pt`:

  ```sh
  curl -fsSL https://raw.githubusercontent.com/CluvexStudio/aether/main/aether.sh -o aether.sh && chmod +x aether.sh && ./aether.sh install
  ```

## Usage

```sh
python aether_tui.py
```

| Key | Action |
| --- | --- |
| `q` | quit, which also stops aether and psiphon |
| `r` | run the health checks now |

| Option | Meaning |
| --- | --- |
| `--aether PATH` | the aether binary to run (default: `aether` on `PATH`) |
| `--data-dir DIR` | where aether keeps its identity files (default: `~/.aether-tui`) |
| `--no-spawn` | don't start aether; only watch the two ports |

Keep the data directory. Deleting it makes aether register a new device, and Cloudflare rate-limits that.

Run `termux-wake-lock` first if you want the tunnel to stay up while the screen is off.
