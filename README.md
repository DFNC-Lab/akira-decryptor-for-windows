# Akira Ransomware Decryptor

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![REUSE](https://img.shields.io/badge/REUSE-compliant-green.svg)](https://reuse.software/)
![](https://komarev.com/ghpvc/?username=DFNC-Lab&repo=akira-decryptor-for-windows)


## What is this?

If your files were encrypted by the **Akira ransomware** (files ending in `.akira`), this tool can **recover them without paying the ransom**. It uses your computer's GPU to find the encryption keys that Akira used, then restores your original files.

**Recovery speed:** ~15 seconds per file on an NVIDIA RTX 4060 (~2 hours for 500 files).

**Supported file types:** PNG, JPEG, PDF, ZIP, DOCX, XLSX, PPTX, DOC, XLS, PPT, HWP, SQLite

## Requirements

- **Operating system:** Windows 10 or later
- **GPU:** NVIDIA GPU with CUDA support and 4GB+ VRAM (for Step 2 only)

## How it works

Akira encrypts files using two ciphers (KCipher-2 and ChaCha8) with keys derived from a predictable Windows timer value (`QueryPerformanceCounter`). This tool:

1. **Estimates** when the encryption happened (from log files and system timestamps).
2. **Searches** all possible timer values using your GPU until it finds the right keys.
3. **Decrypts** your files using the recovered keys.

> Akira encrypts the first and last block of each region with KCipher-2, and the blocks in between with ChaCha8. The supported formats above provide known file headers, so the KCipher-2 key is always recoverable. The ChaCha8 key requires known content in the middle blocks. Regions too small to have middle blocks (128 KB or less) do not need it.

## Usage

> Run **AKIRA DECRYPTOR.exe** to launch the GUI for decrypting infected files, which guides you through all three steps automatically.

### Step 1. Estimate QPC

Run this on the **infected PC**. It reads the Akira ransom note timestamp and Windows Event Log boot records to estimate the QPC reference value needed for seed recovery. The output values are automatically passed to Step 2 when using the GUI.


<p align="center">
  <img src="https://github.com/user-attachments/assets/427e133c-5f64-4f31-bef8-3078274cb123" width="80%" alt="Step 1 — QPC Estimation">
</p>

```
Step1_QPCEstimator.exe [--log <path>] [--tz <offset>]
```

| Parameter | Description |
|-----------|-------------|
| `--log <path>` | Path to Akira log file (auto-detected from `Log-*.txt` in current folder if omitted) |
| `--tz <offset>` | Victim PC timezone, e.g. `+09:00` (uses system timezone if omitted) |

### Step 2. Find Seeds

Searches for the encryption seeds using GPU brute-force. For each `.akira` file, it tries candidate QPC values and verifies them against the file's known header bytes. Results are saved to `found_seeds_*.csv`.

<p align="center">
  <img src="https://github.com/user-attachments/assets/d85c45df-12ec-46c3-8b00-8ca51a8e0ddb" width="80%" alt="Step 2 — Seed Recovery">
</p>

```
Step2_SeedScanner.exe <root_path> <timestamp> <ref_qpc>
                    [--max-offset <ns>] [--max-batch <ns>]
```

| Parameter | Description |
|-----------|-------------|
| `<root_path>` | Directory containing `.akira` files to scan |
| `<timestamp>` | Reference timestamp from Step 1 (`"YYYY-MM-DD HH:MM:SS.mmm"`) |
| `<ref_qpc>` | Reference QPC value from Step 1 (decimal) |
| `--max-offset <ns>` | Maximum Yarrow inter-call gap in nanoseconds (default: `10000000`) |
| `--max-batch <ns>` | Per-file QPC lookback window in nanoseconds (default: `1000000000`) |

### Step 3. Decrypt Files

Restores the original files using the recovered seeds. Automatically detects the encryption mode (full, half, or partial) from the `.akira` footer. Decrypted files are written next to the originals with the `.akira` extension removed.

<p align="center">
  <img src="https://github.com/user-attachments/assets/591eaf4b-5c3a-4f13-ab49-8511eef377be" width="80%" alt="Step 3 — Decryption">
</p>

```
Step3_FileDecryptor.exe --key <hex32> --iv <hex32> --input <path>
                      [--output <path>] [--mode full|half|partial]
                      [--chacha-key <hex32>] [--chacha-iv <hex16>]
```

| Parameter | Description |
|-----------|-------------|
| `--key <hex32>` | 128-bit **KCipher-2** key (32 hex characters) |
| `--iv <hex32>` | 128-bit **KCipher-2** IV (32 hex characters) |
| `--input <path>` | Path to the encrypted `.akira` file |
| `--output <path>` | Output path (default: strip `.akira` extension) |
| `--mode full\|half\|partial` | Encryption mode (default: `full`) |
| `--chacha-key <hex32>` | 128-bit **ChaCha8** key for middle blocks (32 hex characters) |
| `--chacha-iv <hex16>` | 64-bit **ChaCha8** IV (16 hex characters) |

## FAQ

**Q: I don't have an NVIDIA GPU. Can I still use this?**
A: The seed search (Step 2) requires an NVIDIA GPU with CUDA support. Steps 1 and 3 run on the CPU. If you don't have a suitable GPU, you can run Step 2 on a different machine with one and transfer the `found_seeds_*.csv` result file back.

**Q: How long does recovery take?**
A: It depends on your GPU and how many files were encrypted. On an RTX 4060, each file takes about 15 seconds. A folder with 500 encrypted files would take roughly 2 hours.

**Q: Which files can be recovered?**
A: Any `.akira` file whose original format is one of the 12 supported types (PNG, JPEG, PDF, ZIP, DOCX, XLSX, PPTX, DOC, XLS, PPT, HWP, SQLite). These formats have known file headers that allow the tool to verify when the correct key is found.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

### Third-Party Libraries

- [GNU Nettle/Hogweed](https://www.lysator.liu.se/~nisse/nettle/) 3.10.2 (LGPL-3.0) — [source](https://ftp.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz)
- [GNU GMP](https://gmplib.org/) 6.3.0 (LGPL-3.0) — [source](https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) (MIT)

Per LGPL-3.0 Section 4, you may relink `SeedToKey.exe` with your own versions of these libraries using the provided source code and build instructions.
