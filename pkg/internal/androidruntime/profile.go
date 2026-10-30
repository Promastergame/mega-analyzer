package androidruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"mega-analyzer/pkg/internal/antivm"
)

// Mode selects the Android runtime tier.
type Mode string

const (
	ModeMini       Mode = "mini"
	ModeAndroidSDK Mode = "android-sdk"
)

// Profile stores a reproducible Android runtime configuration.
type Profile struct {
	Name      string          `json:"name"`
	Mode      Mode            `json:"mode"`
	AVDName   string          `json:"avd_name"`
	Device    string          `json:"device"`
	Locale    string          `json:"locale"`
	Timezone  string          `json:"timezone"`
	Network   NetworkProfile  `json:"network"`
	Snapshot  SnapshotProfile `json:"snapshot"`
	Display   DisplayProfile  `json:"display"`
	MITM      MITMProfile     `json:"mitm"`
	SystemTag string          `json:"system_tag"`
	AntiVM    AntiVMProfile   `json:"anti_vm"`
	LabDNS    LabDNSProfile   `json:"lab_dns"`
}

// NetworkProfile controls emulator networking in a reproducible way.
type NetworkProfile struct {
	WifiEnabled bool     `json:"wifi_enabled"`
	DNSServers  []string `json:"dns_servers,omitempty"`
	HTTPProxy   string   `json:"http_proxy,omitempty"`
	NetSpeed    string   `json:"net_speed,omitempty"`
	NetDelay    string   `json:"net_delay,omitempty"`
}

// DisplayProfile controls how the Android Emulator window is rendered.
// Mode "headless" keeps CI-friendly defaults, while "scrcpy" opens a
// hardware-accelerated, clean device window that pairs well with scrcpy-style
// mirroring/recording workflows.
type DisplayProfile struct {
	Mode       string `json:"mode,omitempty"`
	Skin       string `json:"skin,omitempty"`
	GPU        string `json:"gpu,omitempty"`
	NoAudio    bool   `json:"no_audio"`
	NoBootAnim bool   `json:"no_boot_anim"`
}

// MITMProfile configures lab-safe interception for owned applications.
type MITMProfile struct {
	Enabled             bool   `json:"enabled"`
	HTTPProxy           string `json:"http_proxy,omitempty"`
	CACertPath          string `json:"ca_cert_path,omitempty"`
	InstallUserCA       bool   `json:"install_user_ca"`
	AllowUserCAForApps  bool   `json:"allow_user_ca_for_apps"`
	CapturePath         string `json:"capture_path,omitempty"`
	RedactAuthorization bool   `json:"redact_authorization"`
}

// SnapshotProfile controls snapshot boot/save behavior.
type SnapshotProfile struct {
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name,omitempty"`
	StoragePath string `json:"storage_path,omitempty"`
	ColdBoot    bool   `json:"cold_boot"`
	SaveOnExit  bool   `json:"save_on_exit"`
	LoadOnStart bool   `json:"load_on_start"`
}

// AntiVMProfile configures the anti-VM evasion engine.
type AntiVMProfile struct {
	Enabled       bool   `json:"enabled"`
	DeviceModel   string `json:"device_model,omitempty"`
	RandomizeIMEI bool   `json:"randomize_imei"`
	SensorNoise   bool   `json:"sensor_noise"`
	PatchBattery  bool   `json:"patch_battery"`
	PatchNetwork  bool   `json:"patch_network"`
	PatchOperator bool   `json:"patch_operator"`
}

// LabDNSProfile configures the built-in Lab DNS sinkhole server.
type LabDNSProfile struct {
	Enabled        bool                 `json:"enabled"`
	ListenAddr     string               `json:"listen_addr,omitempty"`
	Upstream       string               `json:"upstream,omitempty"`
	BlockAll       bool                 `json:"block_all"`
	BlockSafetyNet bool                 `json:"block_safetynet"`
	SinkholeRules  []SinkholeRuleConfig `json:"sinkhole_rules,omitempty"`
}

// SinkholeRuleConfig is a domain-based DNS interception rule.
type SinkholeRuleConfig struct {
	Pattern string `json:"pattern"`
	Target  string `json:"target,omitempty"`
	Name    string `json:"name,omitempty"`
}

// ToEvasionConfig converts the profile's AntiVM settings to the antivm package config.
func (p AntiVMProfile) ToEvasionConfig() antivm.EvasionConfig {
	return antivm.EvasionConfig{
		Enabled:       p.Enabled,
		DeviceModel:   p.DeviceModel,
		RandomizeIMEI: p.RandomizeIMEI,
		SensorNoise:   p.SensorNoise,
		PatchBattery:  p.PatchBattery,
		PatchNetwork:  p.PatchNetwork,
		PatchOperator: p.PatchOperator,
	}
}

// DefaultProfile returns a sane Android SDK profile with networking constrained by default.
func DefaultProfile() Profile {
	return Profile{
		Name:      "android-lab",
		Mode:      ModeAndroidSDK,
		AVDName:   "MegaAnalyzer_API_35",
		Device:    "pixel_7",
		Locale:    "en-US",
		Timezone:  "UTC",
		SystemTag: "google_apis",
		Network: NetworkProfile{
			WifiEnabled: false,
			NetSpeed:    "full",
			NetDelay:    "none",
		},
		Snapshot: SnapshotProfile{
			Enabled:     true,
			Name:        "clean",
			SaveOnExit:  false,
			LoadOnStart: true,
		},
		Display: DisplayProfile{
			Mode:       "headless",
			GPU:        "swiftshader_indirect",
			NoAudio:    true,
			NoBootAnim: true,
		},
		MITM: MITMProfile{
			InstallUserCA:       true,
			RedactAuthorization: true,
		},
		AntiVM: AntiVMProfile{
			Enabled:       true,
			RandomizeIMEI: true,
			SensorNoise:   true,
			PatchBattery:  true,
			PatchNetwork:  true,
			PatchOperator: true,
		},
		LabDNS: LabDNSProfile{
			Enabled:        true,
			ListenAddr:     "127.0.0.1:15353",
			Upstream:       "",
			BlockSafetyNet: true,
		},
	}
}

// LoadProfile loads a runtime profile from JSON.
func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return Profile{}, fmt.Errorf("parse android runtime profile: %w", err)
	}
	profile.Normalize()
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// Normalize applies defaults for omitted values.
func (p *Profile) Normalize() {
	defaults := DefaultProfile()
	if p.Name == "" {
		p.Name = defaults.Name
	}
	if p.Mode == "" {
		p.Mode = defaults.Mode
	}
	if p.AVDName == "" {
		p.AVDName = defaults.AVDName
	}
	if p.Device == "" {
		p.Device = defaults.Device
	}
	if p.Locale == "" {
		p.Locale = defaults.Locale
	}
	if p.Timezone == "" {
		p.Timezone = defaults.Timezone
	}
	if p.SystemTag == "" {
		p.SystemTag = defaults.SystemTag
	}
	if p.Display.Mode == "" {
		p.Display.Mode = defaults.Display.Mode
	}
	if p.Display.GPU == "" {
		p.Display.GPU = defaults.Display.GPU
	}
	if !p.Display.NoAudio {
		p.Display.NoAudio = defaults.Display.NoAudio
	}
	if !p.Display.NoBootAnim {
		p.Display.NoBootAnim = defaults.Display.NoBootAnim
	}
	if p.MITM.Enabled && p.MITM.HTTPProxy != "" && p.Network.HTTPProxy == "" {
		p.Network.HTTPProxy = p.MITM.HTTPProxy
	}
	if !p.MITM.RedactAuthorization {
		p.MITM.RedactAuthorization = defaults.MITM.RedactAuthorization
	}
	if p.Network.NetSpeed == "" {
		p.Network.NetSpeed = defaults.Network.NetSpeed
	}
	if p.Network.NetDelay == "" {
		p.Network.NetDelay = defaults.Network.NetDelay
	}
	if !p.Network.WifiEnabled && !defaults.Network.WifiEnabled {
		p.Network.WifiEnabled = false
	}
	if !p.Snapshot.Enabled && p.Snapshot.Name == "" && p.Snapshot.StoragePath == "" &&
		!p.Snapshot.ColdBoot && !p.Snapshot.SaveOnExit && !p.Snapshot.LoadOnStart {
		p.Snapshot = defaults.Snapshot
	}

	// LabDNS defaults.
	if p.LabDNS.ListenAddr == "" {
		p.LabDNS.ListenAddr = defaults.LabDNS.ListenAddr
	}
	if p.LabDNS.Upstream == "" {
		p.LabDNS.Upstream = defaults.LabDNS.Upstream
	}
}

// Validate checks that the profile is internally consistent.
func (p Profile) Validate() error {
	switch p.Mode {
	case ModeMini, ModeAndroidSDK:
	default:
		return fmt.Errorf("invalid android runtime mode: %q", p.Mode)
	}
	if p.Mode == ModeAndroidSDK && p.AVDName == "" {
		return fmt.Errorf("android-sdk mode requires avd_name")
	}
	switch p.Display.Mode {
	case "", "headless", "windowed", "scrcpy":
	default:
		return fmt.Errorf("invalid android display mode: %q", p.Display.Mode)
	}
	if p.MITM.Enabled && p.MITM.HTTPProxy == "" && p.Network.HTTPProxy == "" {
		return fmt.Errorf("mitm enabled requires http_proxy")
	}
	if p.MITM.AllowUserCAForApps && p.MITM.CACertPath == "" {
		return fmt.Errorf("mitm allow_user_ca_for_apps requires ca_cert_path")
	}
	return nil
}

// BuildEmulatorArgs converts a profile into safe Android Emulator CLI arguments.
func BuildEmulatorArgs(profile Profile) ([]string, error) {
	profile.Normalize()
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if profile.Mode != ModeAndroidSDK {
		return nil, fmt.Errorf("emulator arguments are only available for android-sdk mode")
	}

	args := []string{"@" + profile.AVDName}

	// If LabDNS is enabled and no explicit DNS servers exist, auto-inject
	// the lab DNS address so the emulator routes all queries through our sinkhole.
	if profile.LabDNS.Enabled && len(profile.Network.DNSServers) == 0 {
		profile.Network.DNSServers = []string{extractHost(profile.LabDNS.ListenAddr)}
	}

	if len(profile.Network.DNSServers) > 0 {
		args = append(args, "-dns-server", strings.Join(profile.Network.DNSServers, ","))
	}
	if profile.Network.HTTPProxy != "" {
		args = append(args, "-http-proxy", profile.Network.HTTPProxy)
	}
	if profile.Network.NetSpeed != "" {
		args = append(args, "-netspeed", profile.Network.NetSpeed)
	}
	if profile.Network.NetDelay != "" {
		args = append(args, "-netdelay", profile.Network.NetDelay)
	}
	if !profile.Network.WifiEnabled {
		args = append(args, "-feature", "-Wifi")
	}

	if !profile.Snapshot.Enabled {
		args = append(args, "-no-snapshot")
	} else {
		if profile.Snapshot.StoragePath != "" {
			args = append(args, "-snapstorage", profile.Snapshot.StoragePath)
		}
		if profile.Snapshot.Name != "" && profile.Snapshot.LoadOnStart {
			args = append(args, "-snapshot", profile.Snapshot.Name)
		}
		if profile.Snapshot.ColdBoot {
			args = append(args, "-no-snapshot-load")
		}
		if !profile.Snapshot.SaveOnExit {
			args = append(args, "-no-snapshot-save")
		}
	}

	// Timezone.
	if profile.Timezone != "" {
		args = append(args, "-timezone", profile.Timezone)
	}

	// Display / rendering mode. "scrcpy" intentionally keeps an emulator
	// window and GPU acceleration enabled so external mirroring tools can attach
	// to a stable, realistic surface instead of a black headless framebuffer.
	if profile.Display.GPU != "" {
		args = append(args, "-gpu", profile.Display.GPU)
	}
	if profile.Display.Skin != "" {
		args = append(args, "-skin", profile.Display.Skin)
	}
	if profile.Display.Mode == "headless" {
		args = append(args, "-no-window")
	}
	if profile.Display.NoAudio {
		args = append(args, "-no-audio")
	}
	if profile.Display.NoBootAnim {
		args = append(args, "-no-boot-anim")
	}

	return args, nil
}

// BuildMITMAdbCommands returns post-boot ADB shell commands that make the
// emulator trust the lab CA and proxy for owned-app dynamic analysis.
func BuildMITMAdbCommands(profile Profile) ([]string, error) {
	profile.Normalize()
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if !profile.MITM.Enabled {
		return nil, nil
	}

	commands := []string{
		"shell settings put global http_proxy " + firstNonEmpty(profile.MITM.HTTPProxy, profile.Network.HTTPProxy),
	}
	if profile.MITM.CACertPath != "" && profile.MITM.InstallUserCA {
		commands = append(commands,
			"push "+profile.MITM.CACertPath+" /sdcard/Download/mega-analyzer-ca.crt",
			"shell am start -a android.credentials.INSTALL --ez install_as_uid true --es CERT /sdcard/Download/mega-analyzer-ca.crt",
		)
	}
	if profile.MITM.AllowUserCAForApps {
		commands = append(commands, "shell settings put global captive_portal_mode 0")
	}
	return commands, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// extractHost returns the host part of a host:port address.
func extractHost(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}
