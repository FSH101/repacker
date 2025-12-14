#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DecryptCFG (Windows GUI + CLI)

Формат:
- первые 4 байта: заголовок (просто выводим/логируем)
- остальное: XOR с ключом key = 255 - (i % 255)

GUI:
- выбор входного .cfg
- выбор папки назначения
- кнопка "Декодировать"
- результат сохраняется как <имя>_decrypted.cfg в выбранной папке

Сборка в .exe:
  pyinstaller --onefile --windowed decrypt_gui.py --name DecryptCFG
"""

from __future__ import annotations
import argparse
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox


def decrypt_cfg(input_filename: str | os.PathLike, output_filename: str | os.PathLike) -> tuple[bytes, int]:
    """
    Дешифрует файл согласно алгоритму пользователя.
    Возвращает (header_4bytes, decrypted_body_len).
    """
    input_path = Path(input_filename)
    output_path = Path(output_filename)

    data = input_path.read_bytes()
    if len(data) < 4:
        raise ValueError("Файл слишком короткий (меньше 4 байт).")

    header = data[:4]
    encrypted_body = data[4:]
    decrypted_data = bytearray(len(encrypted_body))

    for i, byte_val in enumerate(encrypted_body):
        key = 255 - (i % 255)
        decrypted_data[i] = byte_val ^ key

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(decrypted_data)

    return header, len(decrypted_data)


def default_output_path(input_path: Path, out_dir: Path) -> Path:
    # Сохраняем расширение, добавляя суффикс
    stem = input_path.stem
    suffix = input_path.suffix or ".cfg"
    return out_dir / f"{stem}_decrypted{suffix}"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DecryptCFG")
        self.resizable(False, False)

        self.in_var = tk.StringVar(value="")
        self.out_dir_var = tk.StringVar(value=str(Path.cwd()))

        pad = {"padx": 10, "pady": 6}

        # Input row
        tk.Label(self, text="Файл .cfg (вход):").grid(row=0, column=0, sticky="w", **pad)
        tk.Entry(self, textvariable=self.in_var, width=52).grid(row=0, column=1, **pad)
        tk.Button(self, text="Выбрать…", command=self.pick_input).grid(row=0, column=2, **pad)

        # Output folder row
        tk.Label(self, text="Папка (выход):").grid(row=1, column=0, sticky="w", **pad)
        tk.Entry(self, textvariable=self.out_dir_var, width=52).grid(row=1, column=1, **pad)
        tk.Button(self, text="Выбрать…", command=self.pick_out_dir).grid(row=1, column=2, **pad)

        # Action
        tk.Button(self, text="Декодировать", command=self.run_decrypt, width=20).grid(row=2, column=1, **pad)

        # Status box
        self.status = tk.Text(self, width=72, height=10, wrap="word")
        self.status.grid(row=3, column=0, columnspan=3, padx=10, pady=(0, 10))
        self.status.configure(state="disabled")

        self.log("Готово. Выбери файл .cfg и папку назначения.")

    def log(self, msg: str) -> None:
        self.status.configure(state="normal")
        self.status.insert("end", msg + "\n")
        self.status.see("end")
        self.status.configure(state="disabled")

    def pick_input(self) -> None:
        path = filedialog.askopenfilename(
            title="Выбери .cfg файл",
            filetypes=[("CFG files", "*.cfg"), ("All files", "*.*")]
        )
        if path:
            self.in_var.set(path)

    def pick_out_dir(self) -> None:
        path = filedialog.askdirectory(title="Выбери папку для результата")
        if path:
            self.out_dir_var.set(path)

    def run_decrypt(self) -> None:
        in_path = Path(self.in_var.get().strip().strip('"'))
        out_dir = Path(self.out_dir_var.get().strip().strip('"'))

        if not in_path.exists() or not in_path.is_file():
            messagebox.showerror("Ошибка", "Входной файл не найден.")
            return

        if not out_dir.exists():
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать папку выхода:\n{e}")
                return

        out_path = default_output_path(in_path, out_dir)

        self.log(f"Вход:  {in_path}")
        self.log(f"Выход: {out_path}")

        try:
            header, out_len = decrypt_cfg(in_path, out_path)
            self.log(f"Заголовок (HEX): {header.hex().upper()}")
            self.log(f"Ок. Записано байт: {out_len}")
            messagebox.showinfo("Готово", f"Расшифровано!\n\n{out_path}")
        except Exception as e:
            self.log(f"Ошибка: {e}")
            messagebox.showerror("Ошибка", str(e))


def cli_main() -> int:
    p = argparse.ArgumentParser(description="DecryptCFG: XOR decrypt cfg with 4-byte header.")
    p.add_argument("input", nargs="?", help="input .cfg path")
    p.add_argument("-o", "--output", help="output file path (optional). If not set, uses <stem>_decrypted<suffix> in current dir.")
    p.add_argument("--gui", action="store_true", help="run GUI (default if no args)")
    args = p.parse_args()

    if args.gui or not args.input:
        app = App()
        app.mainloop()
        return 0

    in_path = Path(args.input)
    if not in_path.exists():
        print("ERROR: input file not found:", in_path)
        return 2

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = default_output_path(in_path, Path.cwd())

    try:
        header, out_len = decrypt_cfg(in_path, out_path)
        print("Header (HEX):", header.hex().upper())
        print("Wrote bytes:", out_len)
        print("Saved to:", out_path)
        return 0
    except Exception as e:
        print("ERROR:", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli_main())
