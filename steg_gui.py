#!/usr/bin/env python3
"""Desktop GUI for secure steganography workflows."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from steg_secure import StegError, hide_flow, reveal_flow


class StegApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("檔案加密隱寫系統")
        self.root.geometry("860x530")
        self.root.minsize(860, 530)
        self.root.configure(bg="#0B0B0D")

        self.bg = "#0B0B0D"
        self.panel = "#15171A"
        self.panel_alt = "#1B1E22"
        self.text = "#F4F2EB"
        self.muted = "#A6A7AA"
        self.accent = "#F26A1B"
        self.accent_hover = "#FF7E35"
        self.border = "#2A2E34"

        self.desktop_dir = self._detect_desktop_dir()
        self.status_var = tk.StringVar(value="就緒")
        self.hide_input_var = tk.StringVar()
        self.hide_cover_var = tk.StringVar()
        self.hide_output_var = tk.StringVar(value=str(self._next_available_file(self.desktop_dir, "stego", ".png")))
        self.hide_password_var = tk.StringVar()

        self.reveal_input_var = tk.StringVar()
        self.reveal_output_var = tk.StringVar(value=str(self.desktop_dir))
        self.reveal_password_var = tk.StringVar()
        self.reveal_unpack_var = tk.BooleanVar(value=True)

        self._setup_style()
        self._build_ui()

    def _detect_desktop_dir(self) -> Path:
        desktop = Path.home() / "Desktop"
        if desktop.exists() and desktop.is_dir():
            return desktop
        return Path.cwd()

    def _next_available_file(self, base_dir: Path, stem: str, suffix: str) -> Path:
        candidate = base_dir / f"{stem}{suffix}"
        if not candidate.exists():
            return candidate
        idx = 1
        while True:
            candidate = base_dir / f"{stem}_{idx}{suffix}"
            if not candidate.exists():
                return candidate
            idx += 1

    def _setup_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("App.TFrame", background=self.bg)
        style.configure("Card.TFrame", background=self.panel, borderwidth=1, relief=tk.SOLID)
        style.configure("Inner.TFrame", background=self.panel_alt)

        style.configure("Title.TLabel", background=self.bg, foreground=self.text, font=("Avenir Next", 20, "bold"))
        style.configure("Sub.TLabel", background=self.bg, foreground=self.muted, font=("Avenir Next", 11))
        style.configure(
            "Section.TLabel", background=self.panel, foreground=self.text, font=("Avenir Next", 12, "bold")
        )
        style.configure("Label.TLabel", background=self.panel, foreground=self.text, font=("Avenir Next", 10))
        style.configure("Status.TLabel", background=self.panel_alt, foreground=self.accent, font=("Avenir Next", 10))

        style.configure(
            "TNotebook",
            background=self.bg,
            borderwidth=0,
            tabmargins=[0, 0, 0, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=self.panel,
            foreground=self.muted,
            padding=(16, 10),
            font=("Avenir Next", 11, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.accent), ("active", self.panel_alt)],
            foreground=[("selected", "#FFFFFF"), ("active", self.text)],
        )

        style.configure(
            "TButton",
            background=self.accent,
            foreground="#FFFFFF",
            borderwidth=0,
            focusthickness=0,
            padding=(12, 8),
            font=("Avenir Next", 10, "bold"),
        )
        style.map(
            "TButton",
            background=[("active", self.accent_hover), ("pressed", "#D55713")],
            foreground=[("disabled", "#777777")],
        )

        style.configure(
            "TEntry",
            fieldbackground="#101215",
            background="#101215",
            foreground=self.text,
            bordercolor=self.border,
            lightcolor=self.border,
            darkcolor=self.border,
            insertcolor=self.text,
            padding=6,
        )
        style.map("TEntry", bordercolor=[("focus", self.accent)], lightcolor=[("focus", self.accent)])

        style.configure(
            "TCheckbutton",
            background=self.panel,
            foreground=self.text,
            font=("Avenir Next", 10),
        )
        style.map("TCheckbutton", foreground=[("active", self.text)])

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=16, style="App.TFrame")
        main.pack(fill=tk.BOTH, expand=True)

        accent_strip = tk.Frame(main, height=4, bg=self.accent)
        accent_strip.pack(fill=tk.X, pady=(0, 12))

        title = ttk.Label(main, text="INSURGENT-STYLE SECURE STEGO CONSOLE", style="Title.TLabel")
        title.pack(anchor=tk.W, pady=(0, 6))

        desc = ttk.Label(
            main,
            text="流程：壓縮 -> 加密 -> LSB 嵌入 / 提取 -> 驗證 -> 解密 -> 還原",
            style="Sub.TLabel",
        )
        desc.pack(anchor=tk.W, pady=(0, 12))

        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True)

        hide_tab = ttk.Frame(notebook, padding=14, style="App.TFrame")
        reveal_tab = ttk.Frame(notebook, padding=14, style="App.TFrame")
        notebook.add(hide_tab, text="隱藏（Hide）")
        notebook.add(reveal_tab, text="還原（Reveal）")

        self._build_hide_tab(hide_tab)
        self._build_reveal_tab(reveal_tab)

        status_wrap = ttk.Frame(main, style="Inner.TFrame", padding=(10, 8))
        status_wrap.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(status_wrap, text="SYSTEM STATUS", style="Sub.TLabel").pack(side=tk.LEFT)
        status_bar = ttk.Label(status_wrap, textvariable=self.status_var, style="Status.TLabel")
        status_bar.pack(side=tk.LEFT, padx=(10, 0))

    def _build_hide_tab(self, frame: ttk.Frame) -> None:
        card = ttk.Frame(frame, style="Card.TFrame", padding=16)
        card.pack(fill=tk.BOTH, expand=True)
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="EMBED ENCRYPTED PAYLOAD", style="Section.TLabel").grid(
            row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 10)
        )

        ttk.Label(card, text="要隱藏的檔案/資料夾", style="Label.TLabel").grid(row=1, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.hide_input_var).grid(row=1, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(card, text="選擇檔案", command=self._pick_hide_input_file).grid(row=1, column=2, padx=4)
        ttk.Button(card, text="選擇資料夾", command=self._pick_hide_input_dir).grid(row=1, column=3, padx=4)

        ttk.Label(card, text="載體 PNG 圖片", style="Label.TLabel").grid(row=2, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.hide_cover_var).grid(row=2, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(card, text="瀏覽", command=self._pick_hide_cover).grid(row=2, column=2, padx=4)

        ttk.Label(card, text="輸出隱寫圖片", style="Label.TLabel").grid(row=3, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.hide_output_var).grid(row=3, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(card, text="另存新檔", command=self._pick_hide_output).grid(row=3, column=2, padx=4)

        ttk.Label(card, text="加密密碼", style="Label.TLabel").grid(row=4, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.hide_password_var, show="*").grid(
            row=4, column=1, sticky="ew", padx=8, pady=7
        )

        run_btn = ttk.Button(card, text="開始隱藏", command=self._run_hide)
        run_btn.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(18, 6))

    def _build_reveal_tab(self, frame: ttk.Frame) -> None:
        card = ttk.Frame(frame, style="Card.TFrame", padding=16)
        card.pack(fill=tk.BOTH, expand=True)
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="EXTRACT AND DECRYPT", style="Section.TLabel").grid(
            row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 10)
        )

        ttk.Label(card, text="隱寫圖片 (PNG)", style="Label.TLabel").grid(row=1, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.reveal_input_var).grid(row=1, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(card, text="瀏覽", command=self._pick_reveal_input).grid(row=1, column=2, padx=4)

        ttk.Label(card, text="輸出資料夾", style="Label.TLabel").grid(row=2, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.reveal_output_var).grid(row=2, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(card, text="選擇", command=self._pick_reveal_output).grid(row=2, column=2, padx=4)

        ttk.Label(card, text="解密密碼", style="Label.TLabel").grid(row=3, column=0, sticky=tk.W, pady=7)
        ttk.Entry(card, textvariable=self.reveal_password_var, show="*").grid(
            row=3, column=1, sticky="ew", padx=8, pady=7
        )

        ttk.Checkbutton(card, text="自動解壓 recovered_payload.zip", variable=self.reveal_unpack_var).grid(
            row=4, column=0, columnspan=4, sticky=tk.W, pady=8
        )

        run_btn = ttk.Button(card, text="開始還原", command=self._run_reveal)
        run_btn.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(18, 6))

    def _pick_hide_input_file(self) -> None:
        path = filedialog.askopenfilename(title="選擇要隱藏的檔案", initialdir=str(self.desktop_dir))
        if path:
            self.hide_input_var.set(path)

    def _pick_hide_input_dir(self) -> None:
        path = filedialog.askdirectory(title="選擇要隱藏的資料夾", initialdir=str(self.desktop_dir))
        if path:
            self.hide_input_var.set(path)

    def _pick_hide_cover(self) -> None:
        path = filedialog.askopenfilename(
            title="選擇載體 PNG",
            initialdir=str(self.desktop_dir),
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            self.hide_cover_var.set(path)

    def _pick_hide_output(self) -> None:
        suggested = Path(self.hide_output_var.get().strip()) if self.hide_output_var.get().strip() else self._next_available_file(self.desktop_dir, "stego", ".png")
        path = filedialog.asksaveasfilename(
            title="輸出隱寫 PNG",
            defaultextension=".png",
            filetypes=[("PNG images", "*.png")],
            initialdir=str(self.desktop_dir),
            initialfile=suggested.name,
        )
        if path:
            self.hide_output_var.set(path)

    def _pick_reveal_input(self) -> None:
        path = filedialog.askopenfilename(
            title="選擇隱寫 PNG",
            initialdir=str(self.desktop_dir),
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            self.reveal_input_var.set(path)

    def _pick_reveal_output(self) -> None:
        path = filedialog.askdirectory(title="選擇輸出資料夾", initialdir=str(self.desktop_dir))
        if path:
            self.reveal_output_var.set(path)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)
        self.root.update_idletasks()

    def _run_async(self, fn, start_text: str, done_text: str) -> None:
        def worker() -> None:
            self.root.after(0, lambda: self._set_status(start_text))
            try:
                fn()
            except StegError as exc:
                self.root.after(0, lambda: messagebox.showerror("錯誤", str(exc)))
                self.root.after(0, lambda: self._set_status("失敗"))
            except Exception as exc:  # pragma: no cover - GUI safety net
                self.root.after(0, lambda: messagebox.showerror("未預期錯誤", str(exc)))
                self.root.after(0, lambda: self._set_status("失敗"))
            else:
                self.root.after(0, lambda: messagebox.showinfo("完成", done_text))
                self.root.after(0, lambda: self._set_status("完成"))

        threading.Thread(target=worker, daemon=True).start()

    def _run_hide(self) -> None:
        input_path = self.hide_input_var.get().strip()
        cover = self.hide_cover_var.get().strip()
        output = self.hide_output_var.get().strip()
        password = self.hide_password_var.get()

        if not all([input_path, cover, output, password]):
            messagebox.showwarning("缺少欄位", "請完整填寫隱藏功能所需欄位。")
            return

        output_path = Path(output)
        if output_path.exists():
            safe_output = self._next_available_file(
                output_path.parent if output_path.parent.exists() else self.desktop_dir,
                output_path.stem,
                output_path.suffix or ".png",
            )
            self.hide_output_var.set(str(safe_output))
            output = str(safe_output)

        def task() -> None:
            hide_flow(Path(input_path), Path(cover), Path(output), password)

        self._run_async(task, "執行中：正在壓縮、加密與嵌入...", f"隱寫完成：{output}")

    def _run_reveal(self) -> None:
        input_path = self.reveal_input_var.get().strip()
        output_dir = self.reveal_output_var.get().strip()
        password = self.reveal_password_var.get()
        unpack = self.reveal_unpack_var.get()

        if not all([input_path, output_dir, password]):
            messagebox.showwarning("缺少欄位", "請完整填寫還原功能所需欄位。")
            return

        def task() -> None:
            reveal_flow(Path(input_path), Path(output_dir), password, unpack)

        self._run_async(task, "執行中：正在提取、驗證與解密...", f"還原完成：{output_dir}")


def main() -> int:
    root = tk.Tk()
    app = StegApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
