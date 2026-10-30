> This guide describes full-native packages only. For the public core archive, see [README_CORE.md](README_CORE.md) / [Русский](README_CORE.ru.md).

# Mega-Analyzer Release Package

This archive contains the pre-compiled binaries and libraries of Mega-Analyzer.

## 📁 Package Structure

- **`analyzer` / `analyzer.exe`**: Core Go CLI engine.
- **`*.dll` / `*.so`**: Native engine libraries (OmniSec symbolic execution, GNN runtime, lifters).
- **`elixir_server/`** (if included): Pre-compiled private Elixir/OTP server.
- **`QUICKSTART.md`**: Guide to running your first analysis.
- **`FlagiFiles.md`**: Complete CLI options reference.

## 🚀 How to Run

For basic CLI usage:
```bash
./analyzer -t <path_to_apk_or_binary>
```

For the web interface:
```bash
./analyzer -web
```

For the interactive terminal wizard:
```bash
./analyzer -tui -t <path_to_apk_or_binary>
```

## ⚙️ Native Engines Setup

> [!IMPORTANT]
> The main executable `analyzer` / `analyzer.exe` **will not start** without the native library files (`*.dll` / `*.so`) located in the same folder. Ensure they are present next to the executable.

- On Windows: They are loaded automatically if placed next to `analyzer.exe`.
- On Linux: Ensure they are in the same folder as the `analyzer` binary and run using:
  ```bash
  LD_LIBRARY_PATH=. ./analyzer -t <path_to_apk_or_binary>
  ```

## 🌐 Private Elixir Server (Optional)

If your package includes `elixir_server/`, you can launch it for distributed binary analysis:
- Start the server:
  ```bash
  ./elixir_server/bin/omnisec_server start
  ```
- Configure the client `analyzer` to connect to it by passing the server address:
  ```bash
  ./analyzer -t <path_to_apk_or_binary> -sandbox-privserver 127.0.0.1:9339
  ```

---
For more information, bugs, and updates, visit the GitHub repository:
https://github.com/Promastergame/mega-analyzer
