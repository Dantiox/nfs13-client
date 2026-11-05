# nfs13-client

Client adapter tools, patcher, and network diagnostics for connecting **Need for Speed: Most Wanted (2012)** to private and self-hosted `nfs13` servers.

Compatible with the self-hosted online server: [178lavash178-create/nfs13](https://github.com/178lavash178-create/nfs13).

---

## Quick Start

### 1. Patch your client executable

The patcher reads your legal retail `NFS13.exe`, applies transport redirects and standalone profile mode, and writes `NFS13.online.exe` alongside it. The original file is never altered.

```bash
python patch_nfs13.py "D:\Games\Need for Speed Most Wanted\NFS13.exe"
```

* Supported executable: size `13 672 448` bytes
* Base SHA-256: `9571280bb8868cd254e95442181d7bf1d6eafb2156a95d0c38337c7470762c0f`
* Patched output: `NFS13.online.exe`

### 2. Configure hosts redirection

Point the game's network domain names to your server IP address (LAN or VPN IP, e.g. `192.168.1.50`). Add the entries from [hosts.txt](hosts.txt) to your system hosts file:

* **Windows**: `C:\Windows\System32\drivers\etc\hosts`
* **Linux / Steam Deck / Proton**: `/etc/hosts`

```text
192.168.1.50 gosredirector.ea.com
192.168.1.50 gosredirector.online.ea.com
192.168.1.50 gosredirector.scert.ea.com
192.168.1.50 gosredirector.stest.ea.com
192.168.1.50 gosca.ea.com
192.168.1.50 nfs13-pc.blaze.ea.com
192.168.1.50 demangler.ea.com
192.168.1.50 peach.online.ea.com
```

### 3. Launch the game

Start `NFS13.online.exe` and select **Online** in the EasyDrive menu.

---

## Diagnostic Trace Hook (Optional)

Located in `trace_hook/`. A proxy `d3d11.dll` that logs internal session setup, mesh networking, speedlists, and Winsock traffic to `nfs13_trace.log` for troubleshooting. See [trace_hook/README.md](trace_hook/README.md) for compilation and usage instructions.

---

## Legal & Compliance

This toolset is developed for digital preservation and interoperability purposes under Directive 2009/24/EC Article 6 and 17 U.S.C. § 1201(f). No copyrighted game executables, assets, or proprietary libraries are distributed in this repository.

Licensed under the [GNU Affero General Public License v3.0](LICENSE).
