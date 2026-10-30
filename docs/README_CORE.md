# Mega-Analyzer @VERSION@

[Русский](README.ru.md)

This is the **core** release: a standalone analyzer for APK, DEX, Smali,
JAR/Minecraft archives and binary security checks, with HTML/JSON/SARIF reports,
a local Web UI and REST API. No Java, Docker or native libraries are required
for the bundled demonstration.

Run from the unpacked directory:

```sh
./analyzer -t demo/vulnerable-app -report all -sarif
./analyzer -web
./analyzer --api
```

On Windows, use `./analyzer.exe` (PowerShell) or `analyzer.exe` (cmd).
The demo reports are in `analysis_output/`. Web UI opens on port 7474;
the API defaults to port 5000. Its local reference is `/api/docs`.

The optional Rust/Zig/GNN engines and native APK editor are not included in this
core archive. Android live analysis needs a configured device and Android tools;
network scans need access to their explicitly selected target.
See [build variants](https://github.com/Promastergame/mega-analyzer/blob/main/docs/BUILD.md).

Web UI runs at most two scans at once and queues up to eight more.
`MEGA_ANALYZER_SCAN_CONCURRENCY` (1–64) and `MEGA_ANALYZER_WEB_QUEUE_SIZE` (1–128)
configure these limits. Waiting scans can be stopped without starting a process.
Results stay in your workspace until you remove them.

`BUILD.json` records the version, source commit, build time and target platform.
Include it and `analyzer --version` when [reporting a bug](https://github.com/Promastergame/mega-analyzer/issues).
Send vulnerabilities through a [private advisory](https://github.com/Promastergame/mega-analyzer/security/advisories/new).
Review logs before sharing them: analysis reports may contain sample data or secrets.

See [QUICKSTART.md](QUICKSTART.md) and [FlagiFiles.md](FlagiFiles.md).
Mega-Analyzer is dual-licensed under [BSD-3-Clause](LICENSE) OR [GPLv2](COPYING),
at your option. Third-party components retain their own licenses; see [NOTICE.txt](NOTICE.txt).

New major versions will be paid upgrades; downloaded free versions remain usable
without buying an upgrade. You can also commission a feature, integration or
standalone utility:
[upgrades and contacting the author](https://github.com/Promastergame/mega-analyzer/blob/main/docs/SUPPORT.md).
