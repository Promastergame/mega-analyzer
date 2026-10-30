package main

import (
	"fmt"
	"os"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Shell Completion
// ═══════════════════════════════════════════════════════════════════════════════

// CompletionCommand handles shell completion requests
type CompletionCommand struct {
	shell string
}

// NewCompletionCommand creates a new completion command
func NewCompletionCommand(shell string) *CompletionCommand {
	return &CompletionCommand{shell: shell}
}

// Run generates and outputs completion script
func (c *CompletionCommand) Run() error {
	switch strings.ToLower(c.shell) {
	case "bash":
		return c.generateBash()
	case "zsh":
		return c.generateZsh()
	case "fish":
		return c.generateFish()
	default:
		return fmt.Errorf("unsupported shell: %s (supported: bash, zsh, fish)", c.shell)
	}
}

// generateBash generates bash completion script
func (c *CompletionCommand) generateBash() error {
	script := `# analyzer bash completion
_analyzer_completion() {
    local cur prev words cword
    _init_completion || return

    case ${prev} in
        -t|--target|-o|--output)
            _filedir -d
            return
            ;;
        -p|--profile)
            COMPREPLY=($(compgen -W "quick balanced deep paranoid" -- "${cur}"))
            return
            ;;
        -report)
            COMPREPLY=($(compgen -W "short default full all" -- "${cur}"))
            return
            ;;
        -mode)
            COMPREPLY=($(compgen -W "research" -- "${cur}"))
            return
            ;;
        -export-format|--ml-patch-export-format)
            COMPREPLY=($(compgen -W "md json csv" -- "${cur}"))
            return
            ;;
        -ml-patch-min-tier)
            COMPREPLY=($(compgen -W "elite normal trash" -- "${cur}"))
            return
            ;;
        -sandbox-output|--ml-patch-export-output|--export-output)
            _filedir -d
            return
            ;;
        -export-suggestions|--export-pattern-stats|-feedback-file)
            _filedir
            return
            ;;
        -mark-relevant|-mark-noise)
            return
            ;;
        -ml-apply|-chat-approve)
            return
            ;;
    esac

    # General flags
    local flags="-t --target -o --output -p --profile -w --workers -timeout"
    flags="$flags -max-files -max-file-size -max-resource-size -callgraph"
    flags="$flags -correlations -deep-scan -d --debug -q --quiet -no-color"
    flags="$flags -json -no-html -no-json -clean-output -report -keep-temp"
    flags="$flags -dex-only -r --rebuild -b --build --decode --no-sign --no-align --preserve-signature --ks --ks-alias"
    flags="$flags --no-resources --no-smali --copy-original --framework-dir"
    flags="$flags --dex-backend --class-cache --smali-api --smali-jobs --smali-verbose --smali-incremental"
    flags="$flags --baksmali-use-locals --baksmali-seq-labels --baksmali-no-param-regs"
    flags="$flags --compression-mode --spool-threshold-mb"
    flags="$flags -sandbox --sandbox-args --sandbox-duration --sandbox-memory"
    flags="$flags --sandbox-allow-net --win-sandbox --sandbox-vss-revert --sandbox-device"
    flags="$flags --sandbox-time-scale --sandbox-output --enable-kernel-monitor"
    flags="$flags --enable-vss --enable-wfp --enable-api-tracing --enable-time-manip"
    flags="$flags -suggest --ml --history --stats --export-suggestions"
    flags="$flags --ml-confidence --ml-max --ml-patch --ml-patch-fix"
    flags="$flags --ml-patch-include-libs --ml-patch-min-score --ml-patch-min-tier"
    flags="$flags --ml-patch-deprecated --ml-patch-sdk --ml-patch-combination"
    flags="$flags --ml-patch-confidence --ml-patch-priority --ml-patch-cross-lang"
    flags="$flags --mode --explain --explain-result --explain-node --explain-file --explain-format -export-format --export-output"
    flags="$flags --confidence-threshold --mark-relevant --mark-noise"
    flags="$flags --show-feedback --ml-apply --chat-list --chat-approve"
    flags="$flags --ml-patch-backend"
    flags="$flags --pattern-stats --export-pattern-stats --feedback-file"
    flags="$flags -v --version -h --help --list-profiles"
    flags="$flags --enable-media --extract-ps1 --media-scan --media-payload"
    flags="$flags --media-stego --media-scrub --media-recursive-polyglot"
    flags="$flags --obb-scan --obb-data-dir --obb-max-size --obb-json"
    flags="$flags --cache-scan --cache-data-dir --ml-cache-script"
    flags="$flags --cache-stats --cache-clear --cache-prune --cache-prune-days"
    flags="$flags --intercept --port --upstream --record --interactive --frame --net-filter --net-flows"
    flags="$flags --fuzz --fuzz-capture --fuzz-target --fuzz-out --servgen"
    flags="$flags --protocol-spec --from-capture --make-server --privserver"
    flags="$flags --privserver-game --privserver-module --privserver-output"
    flags="$flags --privserver-port --privserver-admin --lab-dns --dns-addr"
    flags="$flags --dns-upstream --dns-sinkhole"
    flags="$flags --deobf-iterations --deobf-min-confidence --enable-deobf-cp"
    flags="$flags --enable-deobf-dce --enable-deobf-opr --enable-deobf-ps"
    flags="$flags --enable-deobf-vr --enable-deobf-mr --enable-name-quality"
    flags="$flags --gnn-model --proguard-map"
    flags="$flags --aeg --ml-ex --ml-ex-apply --ml-ex-list --ml-ex-output"
    flags="$flags --ml-ex-timeout --ml-ex-parallel --ml-ex-json"

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=($(compgen -W "${flags}" -- "${cur}"))
        return
    fi

    # Default to directory completion
    _filedir -d
}

complete -F _analyzer_completion analyzer
`
	fmt.Println(script)
	return nil
}

// generateZsh generates zsh completion script
func (c *CompletionCommand) generateZsh() error {
	script := `#compdef analyzer

_analyzer() {
    local -a commands

    _arguments -C \
        {-t,--target}'[Target directory]:directory:_directories' \
        {-o,--output}'[Output directory]:directory:_directories' \
        {-p,--profile}'[Analysis profile]:((quick\:"Fast scan (~30s)" balanced\:"Balanced (~2min)" deep\:"Deep with call graph (~5min)" paranoid\:"Maximum depth (~10min+)"))' \
        {-w,--workers}'[Number of workers]:number' \
        {-timeout,}'[Analysis timeout in seconds]:number' \
        {-max-files,}'[Limit number of files]:number' \
        {-max-file-size,}'[Max code file size in MB]:number' \
        {-max-resource-size,}'[Max resource file size in MB]:number' \
        {-callgraph,}'[Enable call graph analysis]' \
        {-correlations,}'[Enable cross-file correlations]' \
        {-deep-scan,}'[Enable deep bytecode scanning]' \
        {-d,--debug}'[Enable debug logging]' \
        {-q,--quiet}'[Minimal output]' \
        {-no-color,}'[Disable colored output]' \
        {-json,}'[Output as JSON to stdout]' \
        {-no-html,}'[Skip HTML report generation]' \
        {-no-json,}'[Skip JSON report generation]' \
        {-clean-output,}'[Clean output dir before writing reports]' \
        {-report,}'[Report preset]:((short\:"Short report" default\:"Default report" full\:"Full report" all\:"All reports"))' \
        {-keep-temp,}'[Keep temporary files]' \
        {-dex-only,}'[Analyze DEX code only]' \
        {-r,--rebuild}'[Rebuild APK from directory]' \
        {-b,--build}'[Build APK from directory]' \
        {--decode,}'[Decode APK to directory (no analysis)]' \
        {-no-sign,}'[Skip APK signing]' \
        {-no-align,}'[Skip ZIP alignment]' \
        {--preserve-signature,}'[Keep original signature (experimental)]' \
        {--ks,}'[Keystore for rebuild signing]:keystore:_files' \
        {--ks-alias,}'[Key alias inside keystore]' \
        {--no-resources,}'[Skip resource decoding]' \
        {--no-smali,}'[Skip smali generation]' \
        {--copy-original,}'[Copy original META-INF]' \
        {--framework-dir,}'[Framework directory]:directory:_directories' \
        {--dex-backend,}'[Decode backend]:backend:(auto native baksmali)' \
        {--class-cache,}'[Cache native DEX->Smali per class]' \
        {--smali-api,}'[smali/baksmali API level]:number' \
        {--smali-jobs,}'[smali/baksmali workers]:number' \
        {--smali-verbose,}'[Pass --verbose to smali]' \
        {--smali-incremental,}'[Incremental smali->dex rebuild]' \
        {--baksmali-use-locals,}'[Pass --use-locals to baksmali]' \
        {--baksmali-seq-labels,}'[Pass --sequential-labels to baksmali]' \
        {--baksmali-no-param-regs,}'[Pass --parameter-registers=false to baksmali]' \
        {--compression-mode,}'[Rebuild ZIP mode]:mode:(fast balanced best)' \
        {--spool-threshold-mb,}'[Spool large ZIP entries to temp files]:number' \
        {-sandbox,}'[Run target in sandbox mode]' \
        {--sandbox-args,}'[Sandbox arguments]' \
        {--sandbox-duration,}'[Sandbox runtime in seconds]:number' \
        {--sandbox-memory,}'[Sandbox memory cap in MB]:number' \
        {--sandbox-allow-net,}'[Allow real network access]' \
        {--sandbox-device,}'[Exact adb serial for the selected device]' \
        {--win-sandbox,}'[Enable Windows-native sandbox]' \
        {--sandbox-vss-revert,}'[Auto-revert system changes with VSS]' \
        {--sandbox-time-scale,}'[Time acceleration factor]:number' \
        {--sandbox-output,}'[Sandbox output directory]:directory:_directories' \
        {--enable-kernel-monitor,}'[Enable kernel-level monitoring]' \
        {--enable-vss,}'[Enable VSS snapshots]' \
        {--enable-wfp,}'[Enable WFP network capture]' \
        {--enable-api-tracing,}'[Enable API call tracing]' \
        {--enable-time-manip,}'[Enable time manipulation]' \
        {-suggest,--ml}'[Run ML suggester]' \
        {-history,}'[Show analysis history]' \
        {-stats,}'[Show aggregated statistics]' \
        {--export-suggestions,}'[Export suggestions to JSON]:file:_files' \
        {--ml-confidence,}'[ML confidence threshold]:number' \
        {--ml-max,}'[Max suggestions to show]:number' \
        {--ml-patch,}'[Run ML patch predictor]' \
        {--ml-patch-fix,}'[Generate patch code and diffs]' \
        {--ml-patch-include-libs,}'[Include library code]' \
        {--ml-patch-min-score,}'[Min patch risk score]:number' \
        {--ml-patch-min-tier,}'[Min pattern tier]:((elite\:"Elite tier" normal\:"Normal tier" trash\:"Junk tier"))' \
        {--ml-patch-deprecated,}'[Enable deprecated patterns]' \
        {--ml-patch-sdk,}'[Enable SDK detection]' \
        {--ml-patch-combination,}'[Enable pattern combination]' \
        {--ml-patch-confidence,}'[Min confidence threshold]:number' \
        {--ml-patch-priority,}'[Sort by priority then score]' \
        {--ml-patch-cross-lang,}'[Enable cross-language detection]' \
        {--mode,}'[Patch mode]:((research\:"Security research"))' \
        {--explain,}'[Show detailed explanations]' \
        {--export-format,}'[Export format]:((md\:"Markdown" json\:"JSON" csv\:"CSV"))' \
        {--export-output,}'[Export output path]:directory:_directories' \
        {--confidence-threshold,}'[Confidence threshold]:number' \
        {--mark-relevant,}'[Mark finding as relevant]' \
        {--mark-noise,}'[Mark finding as noise]' \
        {--show-feedback,}'[Show saved feedback]' \
        {--ml-apply,}'[Apply ML suggestions]' \
        {--chat-list,}'[Show learned chat phrases]' \
        {--chat-approve,}'[Approve chat phrases]' \
        {--pattern-stats,}'[Show pattern effectiveness]' \
        {--export-pattern-stats,}'[Export pattern stats]:file:_files' \
        {--feedback-file,}'[Import feedback from JSON]:file:_files' \
        {--ml-patch-backend,}'[Patch backend: smali|dex]:backend:(smali dex)' \
        {-v,--version}'[Show version]' \
        {-h,--help}'[Show help]' \
        {--list-profiles,}'[List analysis profiles]' \
        {--enable-media,}'[Enable deep media forensics]' \
        {--extract-ps1,}'[Generate PowerShell payload-extraction script]' \
        {--media-scan,}'[Enable media file analysis]' \
        {--media-payload,}'[Inject payload into media metadata]' \
        {--media-stego,}'[Hide a file inside media via steganography]:file:_files' \
        {--media-scrub,}'[Scrub all metadata from media files]' \
        {--media-recursive-polyglot,}'[Feed polyglot APK/DEX back into the analyzer]' \
        {--obb-scan,}'[Deep-scan OBB/data/cache directories]' \
        {--obb-data-dir,}'[OBB/data directory]:directory:_directories' \
        {--obb-max-size,}'[Max OBB file size in MB]:number' \
        {--cache-scan,}'[Scan app cache for vulnerabilities]' \
        {--cache-data-dir,}'[Override cache directory]:directory:_directories' \
        {--ml-cache-script,}'[Run ML-Apli-Cache prediction]' \
        {--cache-stats,}'[Show cache statistics]' \
        {--cache-clear,}'[Clear all cache]' \
        {--cache-prune,}'[Prune old cache files]' \
        {--cache-prune-days,}'[Prune files older than N days]:number' \
        {--intercept,}'[Run MITM proxy to intercept game traffic]' \
        {--port,}'[Port to listen on for interception]:number' \
        {--upstream,}'[Upstream server to proxy to]' \
        {--net-filter,}'[Display filter for intercepted traffic]' \
        {--net-flows,}'[Reassemble packets into classified bidirectional flows]' \
        {--make-server,--privserver}'[Generate Elixir/OTP private server]' \
        {--privserver-game,}'[Game name for generated project]' \
        {--privserver-port,}'[TCP port for generated server]:number' \
        {--lab-dns,}'[Run local intercepting DNS server]' \
        {--deobf-iterations,}'[Max deobfuscation iterations]:number' \
        {--deobf-min-confidence,}'[Min deobfuscation confidence]:number' \
        {--gnn-model,}'[Path to GNN weights JSON]:file:_files' \
        {--proguard-map,}'[Path to ProGuard/R8 mapping.txt]:file:_files' \
        {--aeg,}'[Run Automated Exploit Generation]' \
        {--ml-ex,}'[Enable experimental modules]' \
        {--ml-ex-apply,}'[Select experimental modules]' \
        {--ml-ex-list,}'[List experimental modules]' \
        '*:target directory:_directories'
}

_analyzer "$@"
`
	fmt.Println(script)
	return nil
}

// generateFish generates fish completion script
func (c *CompletionCommand) generateFish() error {
	script := `# analyzer fish completion

complete -c analyzer -f

# Target and output
complete -c analyzer -l target -s t -d "Target directory" -r
complete -c analyzer -l output -s o -d "Output directory" -r

# Profile
complete -c analyzer -l profile -s p -d "Analysis profile" -x -a "{quick,balanced,deep,paranoid}"

# Performance
complete -c analyzer -l workers -s w -d "Number of workers"
complete -c analyzer -l timeout -d "Analysis timeout in seconds"
complete -c analyzer -l max-files -d "Limit number of files"
complete -c analyzer -l max-file-size -d "Max code file size in MB"
complete -c analyzer -l max-resource-size -d "Max resource file size in MB"

# Analysis options
complete -c analyzer -l callgraph -d "Enable call graph analysis"
complete -c analyzer -l correlations -d "Enable cross-file correlations"
complete -c analyzer -l deep-scan -d "Enable deep bytecode scanning"

# Output options
complete -c analyzer -l debug -s d -d "Enable debug logging"
complete -c analyzer -l quiet -s q -d "Minimal output"
complete -c analyzer -l no-color -d "Disable colored output"
complete -c analyzer -l json -d "Output as JSON to stdout"
complete -c analyzer -l no-html -d "Skip HTML report generation"
complete -c analyzer -l no-json -d "Skip JSON report generation"
complete -c analyzer -l clean-output -d "Clean output dir before writing reports"
complete -c analyzer -l report -d "Report preset" -x -a "{short,default,full,all}"

# APK/DEX options
complete -c analyzer -l keep-temp -d "Keep temporary files"
complete -c analyzer -l dex-only -d "Analyze DEX code only"

# APK rebuilding / decoding
complete -c analyzer -l rebuild -s r -d "Rebuild APK from directory"
complete -c analyzer -l build -s b -d "Build APK from directory"
complete -c analyzer -l decode -d "Decode APK to directory (no analysis)"
complete -c analyzer -l no-sign -d "Skip APK signing"
complete -c analyzer -l no-align -d "Skip ZIP alignment"
complete -c analyzer -l preserve-signature -d "Keep original signature (experimental)"
complete -c analyzer -l ks -d "Keystore for rebuild signing" -r
complete -c analyzer -l ks-alias -d "Key alias inside keystore"
complete -c analyzer -l no-resources -d "Skip resource decoding"
complete -c analyzer -l no-smali -d "Skip smali generation"
complete -c analyzer -l copy-original -d "Copy original META-INF"
complete -c analyzer -l framework-dir -d "Framework directory for resource decoding"
complete -c analyzer -l dex-backend -d "Decode backend" -x -a "{auto,native,baksmali}"
complete -c analyzer -l class-cache -d "Cache native DEX->Smali per class"
complete -c analyzer -l smali-api -d "smali/baksmali API level"
complete -c analyzer -l smali-jobs -d "smali/baksmali workers"
complete -c analyzer -l smali-verbose -d "Pass --verbose to smali"
complete -c analyzer -l smali-incremental -d "Incremental smali->dex rebuild"
complete -c analyzer -l baksmali-use-locals -d "Pass --use-locals to baksmali"
complete -c analyzer -l baksmali-seq-labels -d "Pass --sequential-labels to baksmali"
complete -c analyzer -l baksmali-no-param-regs -d "Pass --parameter-registers=false to baksmali"
complete -c analyzer -l compression-mode -d "Rebuild ZIP mode" -x -a "{fast,balanced,best}"
complete -c analyzer -l spool-threshold-mb -d "Spool large ZIP entries to temp files"

# Sandbox options
complete -c analyzer -l sandbox -d "Run target in sandbox mode"
complete -c analyzer -l sandbox-args -d "Sandbox arguments"
complete -c analyzer -l sandbox-duration -d "Sandbox runtime in seconds"
complete -c analyzer -l sandbox-memory -d "Sandbox memory cap in MB"
complete -c analyzer -l sandbox-allow-net -d "Allow real network access"

# Windows-native sandbox
complete -c analyzer -l win-sandbox -d "Enable Windows-native sandbox"
complete -c analyzer -l sandbox-vss-revert -d "Auto-revert system changes with VSS"
complete -c analyzer -l sandbox-time-scale -d "Time acceleration factor"
complete -c analyzer -l sandbox-output -d "Sandbox output directory" -r
complete -c analyzer -l enable-kernel-monitor -d "Enable kernel-level monitoring"
complete -c analyzer -l enable-vss -d "Enable VSS snapshots"
complete -c analyzer -l enable-wfp -d "Enable WFP network capture"
complete -c analyzer -l enable-api-tracing -d "Enable API call tracing"
complete -c analyzer -l enable-time-manip -d "Enable time manipulation"

# ML assistant
complete -c analyzer -l suggest -s ml -d "Run ML suggester"
complete -c analyzer -l history -d "Show analysis history"
complete -c analyzer -l stats -d "Show aggregated statistics"
complete -c analyzer -l export-suggestions -d "Export suggestions to JSON" -r
complete -c analyzer -l ml-confidence -d "ML confidence threshold"
complete -c analyzer -l ml-max -d "Max suggestions to show"

# ML patcher
complete -c analyzer -l ml-patch -d "Run ML patch predictor"
complete -c analyzer -l ml-patch-fix -d "Generate patch code and diffs"
complete -c analyzer -l ml-patch-include-libs -d "Include library code"
complete -c analyzer -l ml-patch-min-score -d "Min patch risk score"
complete -c analyzer -l ml-patch-min-tier -d "Min pattern tier" -x -a "{elite,normal,trash}"
complete -c analyzer -l ml-patch-deprecated -d "Enable deprecated patterns"
complete -c analyzer -l ml-patch-sdk -d "Enable SDK detection"
complete -c analyzer -l ml-patch-combination -d "Enable pattern combination"
complete -c analyzer -l ml-patch-confidence -d "Min confidence threshold"
complete -c analyzer -l ml-patch-priority -d "Sort by priority then score"
complete -c analyzer -l ml-patch-cross-lang -d "Enable cross-language detection"

# ML patch mode
complete -c analyzer -l mode -d "Patch mode" -x -a "{research}"

# ML patch export
complete -c analyzer -l explain -d "Show detailed explanations"
complete -c analyzer -l export-format -d "Export format" -x -a "{md,json,csv}"
complete -c analyzer -l export-output -d "Export output path" -r
complete -c analyzer -l confidence-threshold -d "Confidence threshold"

# Feedback
complete -c analyzer -l mark-relevant -d "Mark finding as relevant"
complete -c analyzer -l mark-noise -d "Mark finding as noise"
complete -c analyzer -l show-feedback -d "Show saved feedback"
complete -c analyzer -l ml-apply -d "Apply ML suggestions"
complete -c analyzer -l chat-list -d "Show learned chat phrases"
complete -c analyzer -l chat-approve -d "Approve chat phrases"

# Pattern effectiveness
complete -c analyzer -l pattern-stats -d "Show pattern effectiveness"
complete -c analyzer -l export-pattern-stats -d "Export pattern stats" -r
complete -c analyzer -l feedback-file -d "Import feedback from JSON" -r
complete -c analyzer -l ml-patch-backend -d "Patch backend" -x -a "{smali,dex}"

# Info
complete -c analyzer -l version -s v -d "Show version"
complete -c analyzer -l help -s h -d "Show help"
complete -c analyzer -l list-profiles -d "List analysis profiles"

# Media forensics
complete -c analyzer -l enable-media -d "Enable deep media forensics"
complete -c analyzer -l extract-ps1 -d "Generate PowerShell payload-extraction script"
complete -c analyzer -l media-scan -d "Enable media file analysis"
complete -c analyzer -l media-payload -d "Inject payload into media metadata"
complete -c analyzer -l media-stego -d "Hide a file inside media via steganography" -r
complete -c analyzer -l media-scrub -d "Scrub all metadata from media files"
complete -c analyzer -l media-recursive-polyglot -d "Feed polyglot APK/DEX back into the analyzer"

# OBB / cache scanners
complete -c analyzer -l obb-scan -d "Deep-scan OBB/data/cache directories"
complete -c analyzer -l obb-data-dir -d "OBB/data directory" -r
complete -c analyzer -l obb-max-size -d "Max OBB file size in MB"
complete -c analyzer -l cache-scan -d "Scan app cache for vulnerabilities"
complete -c analyzer -l cache-data-dir -d "Override cache directory" -r
complete -c analyzer -l ml-cache-script -d "Run ML-Apli-Cache prediction"
complete -c analyzer -l cache-stats -d "Show cache statistics"
complete -c analyzer -l cache-clear -d "Clear all cache"
complete -c analyzer -l cache-prune -d "Prune old cache files"
complete -c analyzer -l cache-prune-days -d "Prune files older than N days"

# Private server toolkit
complete -c analyzer -l intercept -d "Run MITM proxy to intercept game traffic"
complete -c analyzer -l port -d "Port to listen on for interception"
complete -c analyzer -l upstream -d "Upstream server to proxy to"
complete -c analyzer -l net-filter -d "Display filter for intercepted traffic"
complete -c analyzer -l net-flows -d "Reassemble packets into classified bidirectional flows"
complete -c analyzer -l make-server -d "Generate Elixir/OTP private server"
complete -c analyzer -l privserver -d "Alias for --make-server"
complete -c analyzer -l privserver-game -d "Game name for generated project"
complete -c analyzer -l privserver-port -d "TCP port for generated server"
complete -c analyzer -l lab-dns -d "Run local intercepting DNS server"

# Deobfuscation
complete -c analyzer -l deobf-iterations -d "Max deobfuscation iterations"
complete -c analyzer -l deobf-min-confidence -d "Min deobfuscation confidence"

# GNN / ProGuard
complete -c analyzer -l gnn-model -d "Path to GNN weights JSON" -r
complete -c analyzer -l proguard-map -d "Path to ProGuard/R8 mapping.txt" -r

# Experimental
complete -c analyzer -l aeg -d "Run Automated Exploit Generation"
complete -c analyzer -l ml-ex -d "Enable experimental modules"
complete -c analyzer -l ml-ex-apply -d "Select experimental modules"
complete -c analyzer -l ml-ex-list -d "List experimental modules"
`
	fmt.Println(script)
	return nil
}

// InstallCompletion installs completion script for the current shell
func InstallCompletion(shell string) error {
	cmd := NewCompletionCommand(shell)
	return cmd.Run()
}

// GetCompletionPath returns the completion script path for a shell
func GetCompletionPath(shell string) (string, error) {
	// os.UserHomeDir resolves HOME on Unix and USERPROFILE on Windows, so this
	// works cross-platform (e.g. zsh/bash under WSL or Git Bash). See plan §2.
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}

	switch strings.ToLower(shell) {
	case "bash":
		// Try .bashrc, .bash_profile, or .bash_login
		bashrc := home + "/.bashrc"
		if _, err := os.Stat(bashrc); err == nil {
			return bashrc, nil
		}
		bashProfile := home + "/.bash_profile"
		if _, err := os.Stat(bashProfile); err == nil {
			return bashProfile, nil
		}
		return bashrc, nil // Default to .bashrc

	case "zsh":
		// Use .zshrc or ZDOTDIR
		zdotdir := os.Getenv("ZDOTDIR")
		if zdotdir == "" {
			zdotdir = home
		}
		return zdotdir + "/.zshrc", nil

	case "fish":
		// Use ~/.config/fish/completions/analyzer.fish
		fishDir := home + "/.config/fish/completions"
		return fishDir + "/analyzer.fish", nil

	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}
}
