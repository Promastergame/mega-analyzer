# `-admin`, the local Web UI, and UTF-8

[Русский](WEB_ADMIN.ru.md)

## Running it

From the project root with Go 1.27.3:

```bash
go build ./pkg/cmd/analyzer
```

Windows:

```powershell
.\analyzer.exe -web -admin
```

Linux, or an already-rooted Android with a suitable binary:

```bash
./analyzer -web -admin
./analyzer -web -admin -web-port 8080
```

- `-admin` works only together with `-web` — not with the standalone REST API, CLI detonation, or the IDE command. Other modes are rejected before any privilege request; analysis options are chosen in the UI.
- Windows: standard UAC, wide-character launch, and a re-check of the process token. A cancelled UAC prompt is not hidden.
- Linux: `sudo --user=root`; the application never reads or stores the password. Without sudo you need an already-elevated terminal.
- Android: only an already-rooted device, with the root manager granting `su -c`. This is not rooting, SELinux bypass, or bootloader unlocking. Windows/Linux host privileges do not grant root on the phone over ADB.
- An already-elevated process is not relaunched. A failed child launch does not create a privilege-request loop. The working directory and Unicode arguments are preserved.

## Local access

Once the OS confirms, the server console prints the full `http://127.0.0.1:7474/?t=…` link. Open it in a normal browser. **The browser is deliberately not launched as administrator/root.** Stop the server with Ctrl+C in its console.

A privileged server accepts only a literal loopback IP; localhost is normalized without DNS. A non-local `MEGA_ANALYZER_HOST` value is refused. A random token is mandatory even on loopback, and a failure to generate one prevents startup. The token is created inside the child process rather than passed to it as an argument. Host/Origin/Fetch-Site checks and the HttpOnly/SameSite=Strict cookie are preserved; Origin is additionally verified by scheme, host and port.

`analyzer.flags*.txt` profiles are automatically disabled for an explicit `-admin`. A profile cannot grant elevation by itself. When using an explicit `-web-ui-token`, it must be 32–256 random URL-safe ASCII characters. Such an explicitly supplied secret can be visible in the process list; prefer autogeneration.

**This is elevated privilege, not isolation.** Analyses and child tools can inherit the server's privileges. For untrusted samples use a disposable VM or lab device, not your main system. The flag does not turn synthetic collectors into real drivers.

## UTF-8

- The Windows console is switched to CP_UTF8 (65001) through the Win32 API, without a shell or `chcp`. With no console attached this is a safe no-op; a failed switch emits a warning. The font and terminal must still support the characters.
- Go/HTTP/JSON stay UTF-8 and no BOM is added. The encodings of samples themselves, binary files, and third-party tool output are not rewritten.
- Flag files accept UTF-8, including a leading UTF-8 BOM; UTF-16 and invalid UTF-8 are rejected.
- Patches are UTF-8 without BOM. Context line endings and binary hunks are preserved so the patch stays applicable.

## Applying a patch

**Pick exactly one:**

- `Mega-Analyzer-full-admin-utf8.patch` — against the original `Mega-Analyzer.zip`: the previous sandbox-v2 work, README and cleanup, plus this stage.
- `Mega-Analyzer-v2-admin-utf8.patch` — on top of the previously delivered `Mega-Analyzer-sandbox-v2.zip`: this stage only.

From the root of the corresponding project, where `go.mod` lives:

```bash
git apply --check /path/to/Mega-Analyzer-v2-admin-utf8.patch
```

Only if the check succeeds:

```bash
git apply --whitespace=nowarn /path/to/Mega-Analyzer-v2-admin-utf8.patch
go build ./pkg/cmd/analyzer
```

For the original archive, substitute the full patch name. Git is required, but creating a repository is not. On Windows you can pass `.\Mega-Analyzer-v2-admin-utf8.patch`. Do not re-save the file as ANSI/UTF-16, and do not apply both patches in sequence. For manually modified sources, resolve the mismatches first.

## Regression checks

```bash
go test ./pkg/cmd/analyzer ./pkg/cmd/analyzer/web
```

The new tests cover the web-only flag, the ban on implicit elevation from a profile, the absence of repeated elevation, Unicode/BOM handling, Windows/POSIX arguments, literal treatment of shell metacharacters, loopback, the token, and Origin. Elevation is stubbed in tests: no real UAC/sudo/su is invoked. A live Windows/Android run and per-device permissions still require separate verification. The IDE and the remaining source modules are untouched.
