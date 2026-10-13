"""Desktop interface and byte-distribution analysis for TUNG-128."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import secrets

from keris128.analysis import analyze_modes, avalanche_modes, byte_entropy, byte_histogram
from keris128.constants import BLOCK_SIZE, KEY_SIZE
from keris128.member_d_container import open_sealed, seal
from keris128.tung import encrypt


class TUNGApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("TUNG-128 — Encrypt, Decrypt & Analysis")
        self.geometry("900x680")
        self.path = tk.StringVar()
        self.key = tk.StringVar()
        self.mode = tk.StringVar(value="CBC")
        self.iv = tk.StringVar()
        self.status = tk.StringVar(value="Choose a file and enter the 16-byte master key as 32 hex characters.")
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="TUNG-128 File Tool", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        row = ttk.Frame(frame); row.pack(fill="x", pady=6)
        ttk.Entry(row, textvariable=self.path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Choose file…", command=self._choose).pack(side="left", padx=6)
        row = ttk.Frame(frame); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Master key (16 bytes, hex)").pack(side="left")
        ttk.Entry(row, textvariable=self.key, width=38, show="•").pack(side="left", padx=8)
        ttk.Label(row, text="Mode").pack(side="left", padx=(16, 4))
        ttk.Combobox(row, textvariable=self.mode, values=("ECB", "CBC", "CFB", "OFB", "CTR"), state="readonly", width=8).pack(side="left")
        row = ttk.Frame(frame); row.pack(fill="x", pady=4)
        ttk.Label(row, text="IV / CTR initial counter (hex)").pack(side="left")
        ttk.Entry(row, textvariable=self.iv, width=38).pack(side="left", padx=8)
        ttk.Button(row, text="Generate", command=self._generate_iv).pack(side="left")
        row = ttk.Frame(frame); row.pack(fill="x", pady=8)
        ttk.Button(row, text="Encrypt…", command=self._encrypt).pack(side="left")
        ttk.Button(row, text="Decrypt…", command=self._decrypt).pack(side="left", padx=6)
        ttk.Button(row, text="Analyze + avalanche", command=self._analyze).pack(side="left")
        ttk.Label(frame, textvariable=self.status, wraplength=850).pack(anchor="w", pady=4)
        self.report = tk.Text(frame, height=9, wrap="word", state="disabled")
        self.report.pack(fill="x", pady=(4, 8))
        charts = ttk.Frame(frame); charts.pack(fill="both", expand=True)
        self.plain_chart = self._chart(charts, "Plaintext byte histogram")
        self.cipher_chart = self._chart(charts, "Ciphertext byte histograms — all modes")
        ttk.Label(frame, text="Warning: block.py is marked MOCK. Results do not represent a completed cipher or establish security.", foreground="#a33", wraplength=850).pack(anchor="w", pady=(8, 0))

    def _chart(self, parent: ttk.Frame, title: str) -> tk.Canvas:
        box = ttk.LabelFrame(parent, text=title, padding=5); box.pack(side="left", fill="both", expand=True, padx=4)
        canvas = tk.Canvas(box, height=170, background="white", highlightthickness=0); canvas.pack(fill="both", expand=True)
        return canvas

    def _choose(self) -> None:
        path = filedialog.askopenfilename()
        if path: self.path.set(path)

    def _generate_iv(self) -> None:
        self.iv.set(secrets.token_bytes(BLOCK_SIZE).hex())

    def _inputs(self) -> tuple[bytes, bytes, bytes | None, Path]:
        path = Path(self.path.get())
        if not path.is_file(): raise ValueError("Pilih file yang valid terlebih dahulu.")
        key = bytes.fromhex(self.key.get().strip())
        if len(key) != KEY_SIZE: raise ValueError("Key harus 16 byte (32 digit hex) untuk implementasi TUNG-128 saat ini.")
        iv = None
        if self.mode.get() != "ECB":
            value = self.iv.get().strip()
            if not value:
                self._generate_iv(); value = self.iv.get()
            iv = bytes.fromhex(value)
            if len(iv) != BLOCK_SIZE: raise ValueError("IV/counter harus tepat 16 byte (32 digit hex).")
        return path.read_bytes(), key, iv, path

    def _report(self, text: str) -> None:
        self.report.configure(state="normal"); self.report.delete("1.0", "end"); self.report.insert("1.0", text); self.report.configure(state="disabled")

    def _encrypt(self) -> None:
        try:
            data, key, iv, path = self._inputs()
            target = filedialog.asksaveasfilename(initialfile=path.name + ".tung")
            if target:
                envelope, _effective_iv = seal(data, key, self.mode.get(), iv)
                Path(target).write_bytes(envelope)
                self.status.set(f"Encrypted {len(data)} bytes to authenticated file {target}; mode, IV/counter, and tag are included.")
        except (ValueError, OSError) as exc: messagebox.showerror("Encrypt failed", str(exc))

    def _decrypt(self) -> None:
        try:
            path = Path(self.path.get())
            if not path.is_file(): raise ValueError("Pilih file ciphertext yang valid terlebih dahulu.")
            key = bytes.fromhex(self.key.get().strip())
            if len(key) != KEY_SIZE: raise ValueError("Key harus 16 byte (32 digit hex) untuk implementasi TUNG-128 saat ini.")
            result, file_mode, file_iv = open_sealed(path.read_bytes(), key)
            if self.mode.get().upper() != file_mode:
                raise ValueError(f"Mode yang dipilih ({self.mode.get()}) berbeda dari mode berkas ({file_mode}).")
            self.iv.set(file_iv.hex() if file_iv is not None else "")
            target = filedialog.asksaveasfilename(initialfile=path.stem + ".plain")
            if target:
                Path(target).write_bytes(result); self.status.set(f"Integrity verified for {file_mode}; decrypted output saved to {target}.")
        except (ValueError, OSError) as exc: messagebox.showerror("Decrypt failed", str(exc))

    def _draw(self, canvas: tk.Canvas, data: bytes, color: str) -> None:
        canvas.delete("all")
        counts = byte_histogram(data); peak = max(counts, default=0); width = max(canvas.winfo_width(), 300); height = max(canvas.winfo_height(), 120)
        bar = max(1, width / 256)
        if peak:
            for i, count in enumerate(counts):
                y = height - (count / peak) * (height - 14)
                canvas.create_rectangle(i * bar, y, (i + 1) * bar, height, fill=color, outline="")
        canvas.create_text(4, 4, anchor="nw", text=f"{len(data)} bytes | entropy {byte_entropy(data):.3f} bits/byte", fill="#333")

    def _draw_modes(self, canvas: tk.Canvas, outputs: dict[str, bytes]) -> None:
        canvas.delete("all")
        colors = {"ECB": "#3978c5", "CBC": "#e28b19", "CFB": "#17966f", "OFB": "#b32662", "CTR": "#7654a5"}
        series = {mode: byte_histogram(data) for mode, data in outputs.items()}
        peak = max((max(counts) for counts in series.values()), default=0)
        width, height = max(canvas.winfo_width(), 300), max(canvas.winfo_height(), 120)
        for mode, counts in series.items():
            points = []
            for i, count in enumerate(counts):
                x = i * width / 255
                y = height - (count / peak) * (height - 22) if peak else height
                points.extend((x, y))
            if points:
                canvas.create_line(*points, fill=colors[mode], width=1.5)
        for i, (mode, color) in enumerate(colors.items()):
            canvas.create_rectangle(5 + i * 54, 4, 13 + i * 54, 12, fill=color, outline="")
            canvas.create_text(16 + i * 54, 2, anchor="nw", text=mode, fill="#333")

    def _analyze(self) -> None:
        try:
            data, key, iv, _ = self._inputs()
            self._draw(self.plain_chart, data, "#3978c5")
            metrics = analyze_modes(data, key, iv or bytes(BLOCK_SIZE))
            avalanche = avalanche_modes(data, key, iv or bytes(BLOCK_SIZE))
            mode_outputs = {name: encrypt(data, key, name, None if name == "ECB" else (iv or bytes(BLOCK_SIZE))) for name in metrics}
            lines = ["All modes (same input and IV/counter):", "Mode  Plain H  Cipher H  Cipher bytes  PT flip  Key flip"]
            for name, item in metrics.items():
                av = avalanche[name]
                lines.append(f"{name:<5}  {item['plaintext_bits_per_byte']:>8.4f}  {item['ciphertext_bits_per_byte']:>9.4f}  {int(item['ciphertext_bytes']):>12}  {av['plaintext_percent']:>6.2f}%  {av['key_percent']:>7.2f}%")
            lines.extend(["", "PT flip and Key flip are output-bit change percentages after changing the first bit.", "Entropy and avalanche are descriptive tests, not security proofs. ECB ignores IV; use fresh IVs/nonces where the selected mode requires them."])
            self._report("\n".join(lines))
            self._draw_modes(self.cipher_chart, mode_outputs)
            self.status.set("Analysis complete.")
        except (ValueError, OSError) as exc: messagebox.showerror("Analysis failed", str(exc))


if __name__ == "__main__":
    TUNGApp().mainloop()
