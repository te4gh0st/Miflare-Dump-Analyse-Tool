# Miflare Dump Analyse Tool (mdat.py)

![License](https://img.shields.io/badge/license-MIT-blue.svg) 
![Language](https://img.shields.io/badge/language-Python-brightgreen) 

🛠 A powerful command-line utility for analyzing and manipulating MIFARE Classic 1K/4K card dumps.

## ✨ Features

- 🗂 Load and display `.bin` dumps from MIFARE Classic 1K (16 sectors) and 4K (64 sectors) cards
- 🧬 Visual representation of key data structures
- 🔍 Highlight UID, BCC, ATQA, and SAK values
- 🧠 Decode and generate access bits
- 🧮 BCC calculation from custom UIDs
- 🔄 Compare two dumps, with diff-only mode
- 🌍 Multilingual: English (default) and Russian (`--lang ru`)

## 🔧 Installation

Clone the repository and run:

```bash
git clone https://github.com/te4gh0st/Miflare-Dump-Analyse-Tool.git
cd Miflare-Dump-Analyse-Tool
```
## Then run the tool with:
```bash
mdat.py --help
```

---
MIT License

Copyright (c) 2025 (te4gh0st) Vitaly Timtsurak