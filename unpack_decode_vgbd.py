#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decrypt (XOR) + unpack VGBD .img containers that hold Zstandard frames.

Typical workflow it replaces:
  decoder -> produces decrypted .img
  unpack.py -> extracts files

Usage:
  python unpack_decode_vgbd.py encrypted.img -o out_dir
  python unpack_decode_vgbd.py --gui   # simple Tkinter UI

Features:
- Auto-detect: if input already starts with b"VGBD", it skips decrypt.
- --list: list entries (and compressed sizes) without extracting.
- --decoded-out: optionally save decrypted container to disk.
- --keep-paths: keep directory structure from the names table (safe, no path traversal).
- --gui: tiny Tkinter UI (file picker + output folder picker) for end users.

Dependencies:
  pip install zstandard
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path, PurePosixPath

try:
    import zstandard as zstd
except Exception:
    print("ERROR: missing dependency 'zstandard'. Install it with: pip install zstandard", file=sys.stderr)
    raise

VGBD_MAGIC = b"VGBD"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"  # little-endian Zstandard frame magic


def read_u32_le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def decrypt_payload(buf: bytes) -> bytes:
    """
    Decrypt according to decoder.txt:
    - first 4 bytes are header (ignored)
    - remaining bytes: orig[i] = enc[i] XOR (255 - (i % 255))
    """
    if len(buf) < 4:
        raise ValueError("Encrypted file too short (<4 bytes).")

    encrypted_body = buf[4:]
    out = bytearray(len(encrypted_body))
    for i, b in enumerate(encrypted_body):
        key = 255 - (i % 255)
        out[i] = b ^ key
    return bytes(out)


def parse_names(buf: bytes, names_offset: int, count: int) -> list[str]:
    names: list[str] = []
    p = names_offset
    for _ in range(count):
        ln = read_u32_le(buf, p)
        p += 4
        name = buf[p:p + ln].decode("ascii", errors="replace")
        p += ln
        names.append(name)
    return names


def find_frames(buf: bytes, end_off: int) -> list[int]:
    idxs: list[int] = []
    start = 0
    while True:
        i = buf.find(ZSTD_MAGIC, start, end_off)
        if i == -1:
            break
        idxs.append(i)
        start = i + 4
    return idxs


def safe_out_path(out_dir: Path, name: str, keep_paths: bool) -> Path:
    """
    Builds a safe output path.

    keep_paths=False => flatten, replace slashes with "_"
    keep_paths=True  => keep subfolders, but block path traversal / absolute paths.
    """
    name = name.replace("\\", "/")

    if not keep_paths:
        safe = name.replace("/", "_")
        return out_dir / safe

    # Keep paths safely
    p = PurePosixPath(name)

    # Disallow absolute paths and drive-ish prefixes.
    if p.is_absolute():
        p = PurePosixPath(*p.parts[1:])

    # Remove any ".." parts to prevent traversal
    cleaned_parts = [part for part in p.parts if part not in ("..", "")]
    safe_rel = Path(*cleaned_parts) if cleaned_parts else Path("unnamed.bin")

    out_path = (out_dir / safe_rel)

    # Final safety: ensure resolved path stays within out_dir
    try:
        out_dir_res = out_dir.resolve()
        out_path_res = out_path.resolve()
        if out_dir_res not in out_path_res.parents and out_dir_res != out_path_res:
            # Fallback to flattened name
            flat = name.replace("/", "_")
            return out_dir / flat
    except Exception:
        pass

    return out_path


def ensure_vgbd_container(raw_input: bytes, decoded_out: Path | None = None) -> bytes:
    """
    If raw_input is already VGBD => return it.
    Otherwise decrypt and verify it becomes VGBD.
    """
    if raw_input[:4] == VGBD_MAGIC:
        return raw_input

    decrypted = decrypt_payload(raw_input)
    if decoded_out is not None:
        decoded_out.write_bytes(decrypted)

    if decrypted[:4] != VGBD_MAGIC:
        raise ValueError("After decrypt, result is NOT a VGBD container. "
                         "Check that you passed the right file / right decrypt algorithm.")
    return decrypted


def unpack_bytes(container: bytes, out_dir: Path, list_only: bool, keep_paths: bool) -> None:
    if container[:4] != VGBD_MAGIC:
        raise ValueError("Not a VGBD container (missing magic 'VGBD').")

    # From unpack.txt:
    # - count u32 LE at 0x18
    # - names_offset u32 LE at 0x20
    if len(container) < 0x24:
        raise ValueError("VGBD file too short (header truncated).")

    count = read_u32_le(container, 0x18)
    names_offset = read_u32_le(container, 0x20)

    if names_offset <= 0 or names_offset >= len(container):
        raise ValueError(f"Bad names table offset: {names_offset}")

    names = parse_names(container, names_offset, count)
    frames = find_frames(container, names_offset)

    if not frames:
        raise ValueError("No Zstandard frames found before the names table.")

    if len(frames) != len(names):
        print(f"WARNING: frames({len(frames)}) != names({len(names)}). Will unpack min().", file=sys.stderr)

    n = min(len(frames), len(names))

    if list_only:
        print(f"VGBD container: count(header)={count}, names_off=0x{names_offset:X}, frames_found={len(frames)}")
        print("")
        for i in range(n):
            start = frames[i]
            end = frames[i + 1] if i + 1 < len(frames) else names_offset
            print(f"{i:04d}  {names[i]}  frame_off=0x{start:X}  comp_len={end-start}")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    dctx = zstd.ZstdDecompressor()

    for i in range(n):
        start = frames[i]
        end = frames[i + 1] if i + 1 < len(frames) else names_offset
        chunk = container[start:end]

        try:
            raw = dctx.decompress(chunk)
        except Exception as e:
            raise RuntimeError(f"Zstd decompress failed for entry {i} ({names[i]}) at 0x{start:X}") from e

        out_path = safe_out_path(out_dir, names[i], keep_paths=keep_paths)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)

    print(f"Unpacked {n} files into: {out_dir}")


def run_cli(args: argparse.Namespace) -> None:
    src = Path(args.input)
    raw_input = src.read_bytes()

    decoded_out = Path(args.decoded_out) if args.decoded_out else None
    container = ensure_vgbd_container(raw_input, decoded_out=decoded_out)

    unpack_bytes(container, Path(args.out), list_only=args.list, keep_paths=args.keep_paths)


def run_gui() -> None:
    # Minimal Tkinter UI: choose input file + output folder + run.
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except Exception as e:
        raise RuntimeError("Tkinter is not available in this Python build.") from e

    root = tk.Tk()
    root.title("VGBD Unpacker (decrypt + unpack)")
    root.geometry("540x230")
    root.resizable(False, False)

    inp_var = tk.StringVar()
    out_var = tk.StringVar(value=str(Path.cwd() / "out_dir"))
    keep_var = tk.BooleanVar(value=True)

    def pick_input():
        p = filedialog.askopenfilename(title="Choose encrypted or decrypted VGBD .img",
                                       filetypes=[("IMG files", "*.img"), ("All files", "*.*")])
        if p:
            inp_var.set(p)

    def pick_out():
        p = filedialog.askdirectory(title="Choose output folder")
        if p:
            out_var.set(p)

    def do_unpack():
        inp = inp_var.get().strip()
        out = out_var.get().strip()
        if not inp:
            messagebox.showerror("Error", "Choose an input file.")
            return
        if not out:
            messagebox.showerror("Error", "Choose an output folder.")
            return
        try:
            raw_input = Path(inp).read_bytes()
            container = ensure_vgbd_container(raw_input, decoded_out=None)
            unpack_bytes(container, Path(out), list_only=False, keep_paths=keep_var.get())
            messagebox.showinfo("Done", f"Unpacked into:\n{out}")
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    frm = tk.Frame(root, padx=12, pady=12)
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="Input file (.img):").grid(row=0, column=0, sticky="w")
    tk.Entry(frm, textvariable=inp_var, width=54).grid(row=1, column=0, sticky="w")
    tk.Button(frm, text="Browse…", command=pick_input, width=10).grid(row=1, column=1, padx=(8, 0))

    tk.Label(frm, text="Output folder:").grid(row=2, column=0, sticky="w", pady=(10, 0))
    tk.Entry(frm, textvariable=out_var, width=54).grid(row=3, column=0, sticky="w")
    tk.Button(frm, text="Browse…", command=pick_out, width=10).grid(row=3, column=1, padx=(8, 0))

    tk.Checkbutton(frm, text="Keep folder structure from archive", variable=keep_var)\
        .grid(row=4, column=0, sticky="w", pady=(10, 0))

    tk.Button(frm, text="Unpack", command=do_unpack, width=15, height=2)\
        .grid(row=5, column=0, sticky="w", pady=(14, 0))

    tk.Label(frm, text="Tip: build a single .exe via PyInstaller for non-Python users.", fg="gray")\
        .grid(row=6, column=0, sticky="w", pady=(14, 0))

    root.mainloop()


def main() -> None:
    ap = argparse.ArgumentParser(description="Decrypt (XOR) + unpack VGBD .img (Zstandard frames).")
    ap.add_argument("input", nargs="?", help="Path to the encrypted or already-decrypted .img file")
    ap.add_argument("-o", "--out", default="out_dir", help="Output directory (default: out_dir)")
    ap.add_argument("--list", action="store_true", help="Only list entries, do not extract")
    ap.add_argument("--decoded-out", default="", help="Save decrypted container to this file (optional)")
    ap.add_argument("--keep-paths", action="store_true", help="Keep folder structure from names table")
    ap.add_argument("--gui", action="store_true", help="Launch simple GUI (file picker).")

    args = ap.parse_args()

    if args.gui:
        run_gui()
        return

    if not args.input:
        ap.error("input file is required unless you use --gui")

    run_cli(args)


if __name__ == "__main__":
    main()
