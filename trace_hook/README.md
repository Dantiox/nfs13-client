# Network trace hook (d3d11.dll)

Written by **Dantiox**. A small proxy `d3d11.dll` that loads with the game,
hooks parts of its online code and writes what happens to `nfs13_trace.log`
in the game folder. It is only for debugging; you do not need it to play.

Every hook checks the first bytes of its target and is skipped (logged as
`SKIPPED`) if they do not match, so a different exe will not be modified.

| Log tag | Address | What it shows |
| --- | --- | --- |
| `[NOTIFY_GAME_SETUP]` | `0x00BBF3C0` | Session setup: game id, host, mesh address |
| `[START_NETWORK_MESH]` | `0x00BC8630` | Start of peer-to-peer networking and its result |
| `[MESH] …` | `0x00BBDF90` … `0x00BB3820` | Mesh creation and every connect / defer decision |
| `[ADAPTER] …`, `[CONNAPI] AddClient` | `0x00C0FA50` … `0x00B84430` | Peers handed to the network library |
| `[PLAYLIST] Parse`, `Validate` | `0x006EB0D0`, `0x006EA460` | Speedlist parsing and how many events were accepted |
| `[PLAYLIST] EventTable`, `EventLookup` | `0x006E5DC0` | The game's table of valid event ids |
| `[PLAYLIST] AutologLost` | `0x006E7410` | Who raised "Connection to Autolog lost" |
| `NET_*` | Winsock | All UDP/TCP traffic of the game, with hex dumps |

## Use

Windows: put `d3d11.dll` next to the game exe.
Linux / Proton: the same, plus launch option `WINEDLLOVERRIDES="d3d11=n,b" %command%`.

## Build

```bash
make                     # needs i686-w64-mingw32-gcc
# or with zig:
zig cc -target x86-windows-gnu -O2 -shared -s proxy_d3d11.c d3d11.def -o d3d11.dll -lws2_32
```
