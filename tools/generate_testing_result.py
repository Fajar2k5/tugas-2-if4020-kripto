from __future__ import annotations

import argparse
import csv
import html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from keris128.analysis import (
    analyze_modes,
    avalanche_key_by_mode,
    avalanche_plaintext_by_mode,
    byte_histogram,
)
from keris128.constants import BLOCK_SIZE, KEY_SIZE
from keris128.file import read_encrypted, write_encrypted
from keris128.tung import encrypt

DEFAULT_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
DEFAULT_IV = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")
INPUT_DIR = ROOT / "test" / "input"


def write_csv(path: Path, columns: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        writer.writerows(rows)


def plot_histogram(path: Path, mode: str, plaintext: bytes, ciphertext: bytes) -> None:
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.hist(
        [list(plaintext), list(ciphertext)],
        bins=range(257),
        density=True,
        histtype="step",
        label=("Plaintext", "Ciphertext"),
    )
    ax.set(
        title=f"Histogram byte — {mode}",
        xlabel="Nilai byte (0–255)",
        ylabel="Frekuensi relatif",
    )
    ax.set_xlim(0, 255)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def html_table(columns: list[str], rows: list[list[object]]) -> str:
    headers = "\n".join(f"        <th>{html.escape(column)}</th>" for column in columns)
    body = "\n".join(
        "      <tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"""    <table>
      <thead><tr>
{headers}
      </tr></thead>
      <tbody>
{body}
      </tbody>
    </table>"""


def test_files(
    text_data: bytes,
    binary_data: bytes,
    key: bytes,
    iv: bytes,
    output: Path,
) -> list[list[object]]:
    roundtrips: list[list[object]] = []
    saved_ciphertexts = output / "file_outputs" / "ciphertext"
    saved_plaintexts = output / "file_outputs" / "decrypted"
    saved_ciphertexts.mkdir(parents=True, exist_ok=True)
    saved_plaintexts.mkdir(parents=True, exist_ok=True)

    for sample_name, data in (("plaintext.txt", text_data), ("binary.bin", binary_data)):
        for mode in MODES:
            encrypted_path = saved_ciphertexts / f"{sample_name}.{mode.lower()}.tung"
            decrypted_path = saved_plaintexts / f"{sample_name}.{mode.lower()}.bin"
            write_encrypted(
                str(encrypted_path), data, key, mode, None if mode == "ECB" else iv
            )
            recovered = read_encrypted(str(encrypted_path), key, mode)
            passed = recovered == data
            decrypted_path.write_bytes(recovered)
            roundtrips.append([
                sample_name,
                mode,
                len(data),
                "Sesuai/Berhasil" if passed else "Beda/Gagal",
                str(encrypted_path.relative_to(output)),
                str(decrypted_path.relative_to(output)),
            ])
            if not passed:
                raise AssertionError(f"Round-trip gagal: {sample_name}, {mode}")
    return roundtrips


def generate(
    input_path: Path,
    binary_path: Path,
    key: bytes,
    iv: bytes,
    output: Path,
    avalanche_bits: int,
) -> Path:
    data = input_path.read_bytes()
    binary = binary_path.read_bytes()
    if not data or not binary:
        raise ValueError("Berkas input teks dan biner tidak boleh kosong.")
    try:
        input_label = input_path.resolve().relative_to(ROOT)
    except ValueError:
        input_label = input_path.name
    output.mkdir(parents=True, exist_ok=True)
    key_positions = range(min(avalanche_bits, len(key) * 8))
    plaintext_positions = range(min(avalanche_bits, len(data) * 8))

    key_results = avalanche_key_by_mode(
        encrypt, data, key, MODES, iv, bit_positions=key_positions
    )
    plain_results = avalanche_plaintext_by_mode(
        encrypt, data, key, MODES, iv, bit_positions=plaintext_positions
    )
    avalanche_rows = []
    for changed, results in (("Key", key_results), ("Plaintext", plain_results)):
        for mode, result in results.items():
            for sample in result["samples"]:
                avalanche_rows.append([
                    changed,
                    mode,
                    sample["bit"],
                    sample["hamming"],
                    f"{sample['percentage']:.4f}",
                    result["bits_compared"],
                ])
    write_csv(output / "avalanche.csv", [
        "Perubahan", "Mode", "Bit", "Bit ciphertext berubah", "Persentase", "Bit dibandingkan",
    ], avalanche_rows)

    entropy = analyze_modes(data, key, iv)
    ciphertexts = {
        mode: encrypt(data, key, mode, None if mode == "ECB" else iv)
        for mode in MODES
    }
    plain_hist = byte_histogram(data)
    cipher_hist = {mode: byte_histogram(value) for mode, value in ciphertexts.items()}

    summary = []
    for mode in MODES:
        summary.append([
            mode,
            len(data),
            len(ciphertexts[mode]),
            f"{entropy[mode]['plaintext_bits_per_byte']:.4f}",
            f"{entropy[mode]['ciphertext_bits_per_byte']:.4f}",
            key_results[mode]["count"],
            f"{key_results[mode]['average_percentage']:.4f}",
            plain_results[mode]["count"],
            f"{plain_results[mode]['average_percentage']:.4f}",
        ])
    summary_columns = [
        "Mode", "Byte plaintext", "Byte ciphertext", "Entropi plaintext",
        "Entropi ciphertext", "Bit key diuji", "Avalanche key rata-rata (%)",
        "Bit plaintext diuji", "Avalanche plaintext rata-rata (%)",
    ]
    write_csv(output / "summary.csv", summary_columns, summary)

    histogram_columns = ["Nilai byte", "Plaintext"] + [f"{mode} ciphertext" for mode in MODES]
    histogram_rows = [
        [value, plain_hist[value]] + [cipher_hist[mode][value] for mode in MODES]
        for value in range(256)
    ]
    write_csv(output / "histograms.csv", histogram_columns, histogram_rows)
    for mode in MODES:
        plot_histogram(output / f"histogram-{mode}.png", mode, data, ciphertexts[mode])

    roundtrips = test_files(data, binary, key, iv, output)
    write_csv(output / "file_roundtrip.csv", [
        "Sampel", "Mode", "Byte", "Hasil", "Ciphertext", "Hasil dekripsi",
    ], roundtrips)
    avalanche_table = html_table(summary_columns, summary)
    roundtrip_table = html_table(
        ["Sampel", "Mode", "Byte", "Hasil"],
        [row[:4] for row in roundtrips],
    )
    plots = "\n".join(
        f'    <h3>{mode}</h3>\n    <img src="histogram-{mode}.png" alt="Histogram {mode}">'
        for mode in MODES
    )
    report = f"""<!doctype html>
<html lang="id">
  <head>
    <meta charset="utf-8">
    <title>Hasil Pengujian TUNG-128</title>
    <style>
      body {{ font: 15px Arial, sans-serif; max-width: 1000px; margin: 24px auto; }}
      table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; }}
      th, td {{ border: 1px solid #aaa; padding: 6px; text-align: left; }}
      img {{ width: 100%; }}
    </style>
  </head>
  <body>
    <h1>Hasil Pengujian TUNG-128</h1>
    <p>Input teks: {html.escape(str(input_label))} ({len(data)} byte).</p>
    <p>Input biner: {html.escape(binary_path.name)} ({len(binary)} byte).</p>
    <p>Key: <code>{key.hex()}</code>; IV: <code>{iv.hex()}</code>.</p>

    <h2>Avalanche dan entropi</h2>
    <p>Seluruh input dipakai. Per mode, pengujian membalik {key_results[MODES[0]]['count']} bit key dan {plain_results[MODES[0]]['count']} bit plaintext; semua bit ciphertext hasilnya dibandingkan. Entropi maksimum byte adalah 8 bit.</p>
{avalanche_table}
    <p>Rincian tiap bit ada di <a href="avalanche.csv">avalanche.csv</a>.</p>

    <h2>Histogram plaintext dan ciphertext</h2>
    <p>Histogram membandingkan frekuensi relatif byte untuk setiap mode.</p>
{plots}
    <p>Data histogram: <a href="histograms.csv">histograms.csv</a>.</p>

    <h2>Round-trip berkas</h2>
{roundtrip_table}
    <p>Berkas hasil ada di folder <code>file_outputs/</code>. Daftar lengkap: <a href="file_roundtrip.csv">file_roundtrip.csv</a>.</p>

  </body>
</html>
"""
    result = output / "testing_result.html"
    result.write_text(report, encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Buat hasil pengujian TUNG-128.")
    parser.add_argument("--input", type=Path, default=INPUT_DIR / "plaintext.txt")
    parser.add_argument("--binary-input", type=Path, default=INPUT_DIR / "binary.bin")
    parser.add_argument("--key-hex", default=DEFAULT_KEY.hex())
    parser.add_argument("--iv-hex", default=DEFAULT_IV.hex())
    parser.add_argument("--output", type=Path, default=ROOT / "test" / "results")
    parser.add_argument(
        "--avalanche-bits",
        type=int,
        default=32,
        help="Jumlah bit key dan plaintext yang diuji per mode (default: 32)",
    )
    args = parser.parse_args()

    try:
        key, iv = bytes.fromhex(args.key_hex), bytes.fromhex(args.iv_hex)
    except ValueError as error:
        parser.error(f"Key/IV harus berupa hex: {error}")
    if len(key) != KEY_SIZE or len(iv) != BLOCK_SIZE:
        parser.error(f"Key harus {KEY_SIZE} byte dan IV harus {BLOCK_SIZE} byte.")
    for path in (args.input, args.binary_input):
        if not path.is_file():
            parser.error(f"Berkas uji tidak ditemukan: {path}")
    if args.avalanche_bits < 1:
        parser.error("Jumlah bit avalanche harus positif.")

    result = generate(
        args.input,
        args.binary_input,
        key,
        iv,
        args.output,
        args.avalanche_bits,
    )
    print(f"Hasil pengujian tersimpan di {result}")


if __name__ == "__main__":
    main()
