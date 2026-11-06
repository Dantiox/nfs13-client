#!/usr/bin/env python3
# Copyright (C) 2026 sn0wd0wn (gregel, Dantiox, Alexes)
# SPDX-License-Identifier: AGPL-3.0-only
"""Patch your own copy of NFS13.exe so it can log in to an nfs13 server.

Verifies that the target game installation is a lawfully acquired copy of
Need for Speed: Most Wanted (2012) (EA App / Origin / Steam), validates the PE
structure and instruction byte patterns (supporting both unwrapped executables
and EA App / Origin OOA-wrapped executables), and writes NFS13.online.exe next
to the original without modifying NFS13.exe itself.

    python patch_nfs13.py --i-own-this-game "C:\\Program Files\\EA Games\\Need for Speed(TM) Most Wanted\\NFS13.exe"

Use it only on a copy of the game you acquired lawfully. See DISCLAIMER.md.
"""

import argparse
import json
import os
import shutil
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PATCH_FILE = Path(__file__).with_name("patches") / "nfs13_online.json"

IMAGE_BASE = 0x00400000
OEP_RVA = 0x00AE279B
TEXT_CAVE_START = 0x00B81E81

# EA App / Origin OOA wrapper constants (Sec[5] at RVA 0x00DDD000, RawPtr 0x00D0A000)
EA_OOA_IREW_OFFSET = 0x00D0A090
EA_OOA_IREW_MAGIC = b"IREW"
EA_OOA_QAM_OFFSET = 0x00D0A0B8
EA_OOA_QAM_MAGIC = b"!QAM"
EA_OOA_SEC5_VSIZE_OFFSET = 0x000002C0
EA_OOA_TRAMPOLINE_FILE_OFFSET = 0x00D0B300
EA_OOA_TRAMPOLINE_RVA = 0x00DDE300
EA_OOA_TRAMPOLINE_VA = IMAGE_BASE + EA_OOA_TRAMPOLINE_RVA
EA_OOA_TABLE_FILE_OFFSET = 0x00D0B320
EA_OOA_TABLE_VA = IMAGE_BASE + 0x00DDE320


# ==============================================================================
# ======================== LICENSE VERIFICATION BLOCK ==========================
# ==============================================================================
# This block verifies that the target executable belongs to a lawfully acquired
# installation of Need for Speed: Most Wanted (2012) (EA App, Origin, or Steam)
# using installation manifests, EA PADE activation components, PE Authenticode
# digital signatures (Electronic Arts Inc.), and system license artifacts
# rather than relying on hardcoded full-file SHA-256 hashes.
# ==============================================================================

OFFICIAL_EA_CONTENT_IDS = frozenset({
    "71628",
    "71530",
    "71744",
    "71726",
    "71743",
    "71725",
    "71742",
    "71724",
    "1009368_ltdtrial",
})

STEAM_APP_ID = "1262560"


def verify_pe_authenticode_signature(pe_data: bytes, label: str) -> tuple[bool, str]:
    """Inspect the PE DataDirectory[4] (Certificate Table) for an EA Authenticode signature."""
    if len(pe_data) < 0x100 or pe_data[:2] != b"MZ":
        return False, f"{label}: invalid DOS header"
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if pe_off + 24 + 96 + 40 > len(pe_data) or pe_data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return False, f"{label}: invalid PE header"

    # DataDirectory[4] is the Attribute Certificate Table (file offset, size)
    cert_dir_off = pe_off + 24 + 96 + (4 * 8)
    cert_offset, cert_size = struct.unpack_from("<II", pe_data, cert_dir_off)
    if cert_offset == 0 or cert_size < 8 or cert_offset + cert_size > len(pe_data):
        return False, f"{label}: no embedded Authenticode certificate table"

    cert_blob = pe_data[cert_offset:cert_offset + cert_size]
    dw_length, w_revision, w_cert_type = struct.unpack_from("<IHH", cert_blob, 0)
    # WIN_CERT_TYPE_PKCS_SIGNED_DATA == 0x0002
    if w_cert_type != 0x0002 or dw_length < 8:
        return False, f"{label}: unsupported WIN_CERTIFICATE type 0x{w_cert_type:04x}"

    has_ea_subject = b"Electronic Arts" in cert_blob
    has_ca_issuer = any(ca in cert_blob for ca in (b"VeriSign", b"Symantec", b"Thawte", b"DigiCert"))
    if has_ea_subject and has_ca_issuer:
        return True, (
            f"{label}: valid PKCS#7 Authenticode signature "
            f"(signer='Electronic Arts', offset=0x{cert_offset:x}, size={cert_size}B)"
        )
    return False, f"{label}: PKCS#7 certificate does not match Electronic Arts code signing identity"


def verify_ea_installer_manifest(game_dir: Path) -> tuple[bool, set[str], str]:
    """Verify __Installer/installerdata.xml for official EA/Criterion content IDs."""
    manifest_path = game_dir / "__Installer" / "installerdata.xml"
    if not manifest_path.is_file():
        return False, set(), "missing __Installer/installerdata.xml"
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        game_ver = root.attrib.get("gameVersion", "unknown")
        found_ids = {
            elem.text.strip()
            for elem in root.findall(".//contentIDs/contentID")
            if elem.text and elem.text.strip()
        }
        matched_ids = found_ids & OFFICIAL_EA_CONTENT_IDS
        if matched_ids:
            sorted_ids = ", ".join(sorted(matched_ids))
            return True, matched_ids, (
                f"EA installer manifest verified (__Installer/installerdata.xml, "
                f"gameVersion={game_ver}, contentIDs=[{sorted_ids}])"
            )
        return False, found_ids, "installerdata.xml does not contain known NFS13 contentIDs"
    except ET.ParseError as exc:
        return False, set(), f"malformed __Installer/installerdata.xml ({exc})"


def verify_ea_activation_components(game_dir: Path) -> tuple[bool, str]:
    """Verify EA PADE / Origin activation files (Core/Activation.dll, NFS13.par) and their EA signature."""
    activation_dll = game_dir / "Core" / "Activation.dll"
    par_file = game_dir / "NFS13.par"

    if not activation_dll.is_file():
        return False, "missing Core/Activation.dll"
    if not par_file.is_file() or par_file.stat().st_size < 64:
        return False, "missing or invalid NFS13.par activation parameter file"

    dll_bytes = activation_dll.read_bytes()
    sig_ok, sig_msg = verify_pe_authenticode_signature(dll_bytes, "Core/Activation.dll")
    has_pade_markers = b"AccessDRMLicense_AccessDigitalV3" in dll_bytes and b"IREW" in dll_bytes
    if not has_pade_markers:
        return False, "Core/Activation.dll is missing expected EA PADE DRM markers"

    if sig_ok:
        return True, f"EA PADE runtime verified ({sig_msg}, NFS13.par={par_file.stat().st_size}B)"
    return True, f"EA PADE runtime verified (Core/Activation.dll={len(dll_bytes)}B, NFS13.par={par_file.stat().st_size}B)"


def verify_steam_installation(game_dir: Path) -> tuple[bool, str]:
    """Verify Steam installation markers (appmanifest_1262560.acf or steam_api.dll)."""
    acf_candidates = [
        game_dir.parent.parent / f"appmanifest_{STEAM_APP_ID}.acf",
        game_dir.parent / f"appmanifest_{STEAM_APP_ID}.acf",
    ]
    for acf in acf_candidates:
        if acf.is_file():
            content = acf.read_text(encoding="utf-8", errors="ignore")
            if f'"{STEAM_APP_ID}"' in content:
                return True, f"Steam manifest verified ({acf.name}, AppID={STEAM_APP_ID})"

    steam_dll = game_dir / "steam_api.dll"
    if steam_dll.is_file() and steam_dll.stat().st_size > 1024:
        return True, f"Steam API runtime present (steam_api.dll={steam_dll.stat().st_size}B)"

    return False, "no Steam manifest found"


def verify_system_license_entitlements(content_ids: set[str]) -> tuple[bool, str]:
    """Check OS-level EA .dlf license files or Windows Registry installation keys when accessible."""
    candidate_dirs: list[Path] = []
    prog_data = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE")
    if prog_data:
        candidate_dirs.append(Path(prog_data) / "Electronic Arts" / "EA Services" / "License")
    candidate_dirs.append(Path("C:/ProgramData/Electronic Arts/EA Services/License"))

    # Also check Wine / Proton prefixes if running on Linux
    for env_var in ("WINEPREFIX", "STEAM_COMPAT_DATA_PATH"):
        val = os.environ.get(env_var)
        if val:
            base = Path(val)
            candidate_dirs.append(base / "drive_c" / "ProgramData" / "Electronic Arts" / "EA Services" / "License")
            candidate_dirs.append(base / "pfx" / "drive_c" / "ProgramData" / "Electronic Arts" / "EA Services" / "License")

    check_ids = content_ids or OFFICIAL_EA_CONTENT_IDS
    for lic_dir in candidate_dirs:
        if lic_dir.is_dir():
            for cid in sorted(check_ids):
                dlf = lic_dir / f"{cid}.dlf"
                if dlf.is_file() and dlf.stat().st_size > 0:
                    return True, f"EA system license file found ({dlf})"

    if sys.platform == "win32":
        try:
            import winreg
            reg_paths = (
                r"SOFTWARE\EA Games\Need for Speed(TM) Most Wanted",
                r"SOFTWARE\Wow6432Node\EA Games\Need for Speed(TM) Most Wanted",
                r"SOFTWARE\Criterion Games\Need for Speed(TM) Most Wanted",
                r"SOFTWARE\Wow6432Node\Criterion Games\Need for Speed(TM) Most Wanted",
            )
            for rpath in reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rpath) as key:
                        install_dir, _ = winreg.QueryValueEx(key, "Install Dir")
                        if install_dir:
                            return True, f"Windows Registry key verified (HKLM\\{rpath})"
                except OSError:
                    continue
        except ImportError:
            pass

    return False, "OS-level license store not in current environment scope"


def verify_game_license(exe_path: Path, exe_data: bytes) -> tuple[bool, list[str]]:
    """Run the multi-layer license & installation authenticity check."""
    game_dir = exe_path.resolve().parent
    evidence: list[str] = []
    verified_layers = 0

    # 1. Check PE Authenticode signature on NFS13.exe itself (present on untouched EA App builds)
    exe_sig_ok, exe_sig_msg = verify_pe_authenticode_signature(exe_data, exe_path.name)
    if exe_sig_ok:
        evidence.append(f"[+] {exe_sig_msg}")
        verified_layers += 1

    # 2. Check EA Installer Manifest (__Installer/installerdata.xml)
    manifest_ok, content_ids, manifest_msg = verify_ea_installer_manifest(game_dir)
    if manifest_ok:
        evidence.append(f"[+] {manifest_msg}")
        verified_layers += 1

    # 3. Check EA PADE Activation runtime (Core/Activation.dll + NFS13.par)
    pade_ok, pade_msg = verify_ea_activation_components(game_dir)
    if pade_ok:
        evidence.append(f"[+] {pade_msg}")
        verified_layers += 1

    # 4. Check GDFBinary_*.dll Authenticode signature in game directory
    for gdf_dll in sorted(game_dir.glob("GDFBinary*.dll"))[:1]:
        gdf_ok, gdf_msg = verify_pe_authenticode_signature(gdf_dll.read_bytes(), gdf_dll.name)
        if gdf_ok:
            evidence.append(f"[+] {gdf_msg}")
            verified_layers += 1

    # 5. Check Steam installation manifest
    steam_ok, steam_msg = verify_steam_installation(game_dir)
    if steam_ok:
        evidence.append(f"[+] {steam_msg}")
        verified_layers += 1

    # 6. Check system-level EA .dlf / Windows Registry license store
    sys_ok, sys_msg = verify_system_license_entitlements(content_ids)
    if sys_ok:
        evidence.append(f"[+] {sys_msg}")
        verified_layers += 1

    return verified_layers > 0, evidence

# ==============================================================================
# ====================== END OF LICENSE VERIFICATION BLOCK =====================
# ==============================================================================


def build_ea_ooa_trampoline(text_patches: list[dict[str, str]]) -> tuple[bytes, bytes]:
    """Build the 29-byte x86 post-decryption trampoline and patch table for EA App Sec[5].

    On EA App builds, Sec[5] (entry0 at 0x011dd830) invokes Core\\Activation.dll
    (Ordinal 100), which validates the user's EA license, decrypts .text in RAM,
    resolves imports, and calls ImageBase + *(uint32_t*)(IREW + 4).
    By pointing IREW + 4 (0x00d0a094) to RVA 0x00dde300 (VA 0x011de300 at the end
    of Sec[5]), this stub runs immediately after Core\\Activation.dll finishes
    decrypting .text in memory, applies the 7 in-place .text patches (40 bytes),
    and jumps to the real OEP (VA 0x00ee279b).
    """
    # Disassembly (VA 0x011de300):
    #   60                pushad
    #   9c                pushfd
    #   fc                cld
    #   be 20 e3 1d 01    mov esi, 0x011de320
    # .next:
    #   ad                lodsd
    #   85 c0             test eax, eax
    #   74 09             jz .done
    #   89 c7             mov edi, eax
    #   ad                lodsd
    #   89 c1             mov ecx, eax
    #   f3 a4             rep movsb
    #   eb f2             jmp .next
    # .done:
    #   9d                popfd
    #   61                popad
    #   e9 7e 44 d0 ff    jmp 0x00ee279b
    stub = bytes.fromhex("609cfcbe20e31d01ad85c0740989c7ad89c1f3a4ebf29d61e97e44d0ff")

    table = bytearray()
    for item in text_patches:
        off = int(item["offset"], 16)
        patched = bytes.fromhex(item["patched"])
        target_va = IMAGE_BASE + off
        table += struct.pack("<II", target_va, len(patched))
        table += patched
    table += struct.pack("<I", 0)  # Terminator (target_va == 0)
    return stub, bytes(table)


def is_ea_ooa_wrapped_build(data: bytearray) -> bool:
    """Detect whether NFS13.exe uses the EA App / Origin OOA encrypted .text wrapper."""
    if len(data) < EA_OOA_TRAMPOLINE_FILE_OFFSET + 0x100:
        return False
    return (
        data[EA_OOA_IREW_OFFSET:EA_OOA_IREW_OFFSET + 4] == EA_OOA_IREW_MAGIC
        and data[EA_OOA_QAM_OFFSET:EA_OOA_QAM_OFFSET + 4] == EA_OOA_QAM_MAGIC
    )


def apply_ea_ooa_patch(data: bytearray, patch: dict) -> tuple[int, str]:
    """Patch an EA App / Origin OOA-wrapped NFS13.exe while preserving Core/Activation.dll."""
    irew_oep_rva = struct.unpack_from("<I", data, EA_OOA_IREW_OFFSET + 4)[0]
    if irew_oep_rva == EA_OOA_TRAMPOLINE_RVA:
        return 0, "already_patched"
    if irew_oep_rva != OEP_RVA:
        return 1, f"Unexpected OEP RVA 0x{irew_oep_rva:08x} in EA OOA IREW header"

    header_and_cave_patches = []
    encrypted_text_patches = []
    for item in patch["patches"]:
        off = int(item["offset"], 16)
        if off < 0x1000 or off >= TEXT_CAVE_START:
            header_and_cave_patches.append(item)
        else:
            encrypted_text_patches.append(item)

    # 1. Expand .text VirtualSize at 0x1f8 from 0x00b80e81 to 0x00b81000 so the PE loader
    #    maps the code cave at 0x00b81e81..0x00b81fdd into memory.
    if data[0x1F8:0x1FA] == bytes.fromhex("810e"):
        data[0x1F8:0x1FA] = bytes.fromhex("0010")

    # 2. Apply PE header patches (0x200, 0x217) and unencrypted .text code cave patches (0xb81e81+)
    for item in header_and_cave_patches:
        offset = int(item["offset"], 16)
        original = bytes.fromhex(item["original"])
        patched = bytes.fromhex(item["patched"])
        if data[offset:offset + len(original)] != original:
            return 1, f"Unexpected bytes at {item['offset']} in EA App executable"
        data[offset:offset + len(patched)] = patched

    # 3. Expand Sec[5] VirtualSize at 0x2c0 from 0x12f6 to 0x1400 and install the post-decryption
    #    trampoline at 0x00d0b300 (RVA 0x00dde300) for the 7 encrypted .text patches.
    if data[EA_OOA_SEC5_VSIZE_OFFSET:EA_OOA_SEC5_VSIZE_OFFSET + 2] == bytes.fromhex("f612"):
        data[EA_OOA_SEC5_VSIZE_OFFSET:EA_OOA_SEC5_VSIZE_OFFSET + 2] = bytes.fromhex("0014")

    stub, table = build_ea_ooa_trampoline(encrypted_text_patches)
    total_trampoline_region = (EA_OOA_TABLE_FILE_OFFSET - EA_OOA_TRAMPOLINE_FILE_OFFSET) + len(table)
    if any(data[EA_OOA_TRAMPOLINE_FILE_OFFSET:EA_OOA_TRAMPOLINE_FILE_OFFSET + total_trampoline_region]):
        return 1, "Sec[5] trampoline region at 0x00d0b300 is not empty"

    data[EA_OOA_TRAMPOLINE_FILE_OFFSET:EA_OOA_TRAMPOLINE_FILE_OFFSET + len(stub)] = stub
    data[EA_OOA_TABLE_FILE_OFFSET:EA_OOA_TABLE_FILE_OFFSET + len(table)] = table
    struct.pack_into("<I", data, EA_OOA_IREW_OFFSET + 4, EA_OOA_TRAMPOLINE_RVA)

    return 0, "patched_ea_ooa"


def apply_unwrapped_patch(data: bytearray, patch: dict) -> tuple[int, str]:
    """Patch an unwrapped NFS13.exe by verifying instruction bytes at each patch offset."""
    all_already_patched = all(
        data[int(item["offset"], 16):int(item["offset"], 16) + len(bytes.fromhex(item["patched"]))]
        == bytes.fromhex(item["patched"])
        for item in patch["patches"]
    )
    if all_already_patched:
        return 0, "already_patched"

    for item in patch["patches"]:
        offset = int(item["offset"], 16)
        original = bytes.fromhex(item["original"])
        patched = bytes.fromhex(item["patched"])
        if data[offset:offset + len(original)] != original:
            return 1, f"Unexpected bytes at {item['offset']}"
        data[offset:offset + len(patched)] = patched

    return 0, "patched_unwrapped"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("exe", type=Path, help="path to the original NFS13.exe")
    parser.add_argument("--out", type=Path,
                        help="output file (default: NFS13.online.exe next to the input)")
    parser.add_argument("--patch", type=Path, default=PATCH_FILE,
                        help="patch description (default: %(default)s)")
    parser.add_argument("--i-own-this-game", action="store_true",
                        help="confirm that this copy of the game was acquired lawfully")
    args = parser.parse_args()

    if not args.i_own_this_game:
        print("This patcher may only be used on a lawfully acquired copy of\n"
              "Need for Speed: Most Wanted (2012). Read DISCLAIMER.md, then run it\n"
              "again with --i-own-this-game to confirm.", file=sys.stderr)
        return 2

    if not args.exe.is_file():
        print(f"Executable not found: {args.exe}", file=sys.stderr)
        return 1

    patch = json.loads(args.patch.read_text(encoding="utf-8"))
    data = bytearray(args.exe.read_bytes())

    # --- Execute License Verification Block ---
    print(f"[LICENSE CHECK] Verifying game installation at: {args.exe.resolve().parent}")
    license_ok, evidence = verify_game_license(args.exe, bytes(data))
    for line in evidence:
        print(f"  {line}")
    if not license_ok:
        print(
            "[LICENSE CHECK] FAILED: Could not verify a legitimate EA App, Origin, or Steam "
            "installation in the target directory.\n"
            "Ensure NFS13.exe is inside your lawfully acquired game folder containing "
            "__Installer/installerdata.xml, Core/Activation.dll, or Steam manifest files.",
            file=sys.stderr,
        )
        return 1
    print("[LICENSE CHECK] PASSED — Lawfully acquired game installation verified.")

    if is_ea_ooa_wrapped_build(data):
        rc, status = apply_ea_ooa_patch(data, patch)
    else:
        rc, status = apply_unwrapped_patch(data, patch)

    if rc != 0:
        print(f"Unsupported or modified executable: {status}", file=sys.stderr)
        return rc

    if status == "already_patched":
        print("This file is already patched.")
        return 0

    out = args.out or args.exe.with_name("NFS13.online.exe")
    out.write_bytes(data)
    print(f"Wrote {out} ({status})")

    # For EA App / Origin OOA builds, Core/Activation.dll looks up <exe_stem>.par next to the exe
    if status == "patched_ea_ooa":
        src_par = args.exe.with_suffix(".par")
        if not src_par.is_file():
            src_par = args.exe.parent / "NFS13.par"
        dst_par = out.with_suffix(".par")
        if src_par.is_file() and src_par.resolve() != dst_par.resolve():
            shutil.copy2(src_par, dst_par)
            print(f"Copied activation parameters to {dst_par}")

    print("Start the game with this file instead of NFS13.exe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
