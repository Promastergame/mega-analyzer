package media

import (
	"fmt"
	"path/filepath"
	"strings"
)

// screenshot heuristic.
//
// Split from exif.go: exact code move, no logic changes.

// --- Screenshot heuristic ---------------------------------------------------

// screenResolution pairs a pixel size with the device that has it, so the
// verdict can name its evidence instead of asserting "common resolution".
type screenResolution struct {
	W, H   int
	Device string
	// Weight is deliberately lower for desktop/monitor sizes: 1920x1080 and
	// 2560x1440 are also Figma exports, wallpapers, video frames and diffusion
	// model output, so on their own they must not produce a verdict.
	Weight float64
}

var commonScreenResolutionList = []screenResolution{
	// iPhone
	{1170, 2532, "iPhone 12/13/14", 0.8},
	{1179, 2556, "iPhone 14 Pro/15/16", 0.8},
	{1290, 2796, "iPhone 14 Pro Max/15 Plus", 0.8},
	{1206, 2622, "iPhone 16 Pro", 0.8},
	{1320, 2868, "iPhone 16 Pro Max", 0.8},
	{1284, 2778, "iPhone 12/13 Pro Max", 0.8},
	{1125, 2436, "iPhone X/XS/11 Pro", 0.8},
	{1242, 2688, "iPhone XS Max/11 Pro Max", 0.8},
	{828, 1792, "iPhone XR/11", 0.8},
	{750, 1334, "iPhone 6-8/SE2", 0.8},
	{640, 1136, "iPhone 5/SE1", 0.8},
	{1242, 2208, "iPhone 6+/7+/8+", 0.8},
	// Android
	{1080, 1920, "1080p phone", 0.7},
	{1080, 2160, "18:9 Android phone", 0.8},
	{1080, 2280, "19:9 Android phone", 0.8},
	{1080, 2340, "19.5:9 Android phone", 0.8},
	{1080, 2400, "20:9 Android phone", 0.8},
	{1080, 2408, "Samsung Galaxy S22/S23", 0.8},
	{1080, 2412, "Samsung Galaxy A-series", 0.8},
	{1080, 2424, "Pixel 8/9", 0.8},
	{1344, 2992, "Pixel 8/9 Pro", 0.8},
	{1440, 2560, "QHD phone", 0.8},
	{1440, 2960, "Samsung Galaxy S8-S10", 0.8},
	{1440, 3040, "Samsung Galaxy Note 10", 0.8},
	{1440, 3088, "Samsung Galaxy S20-S22 Ultra", 0.8},
	{1440, 3120, "Samsung Galaxy S23/S24 Ultra", 0.8},
	{1440, 3200, "Samsung Galaxy S20-S22", 0.8},
	{720, 1280, "720p phone", 0.6},
	// iPad / tablets
	{1536, 2048, "iPad (4:3)", 0.8},
	{1640, 2360, "iPad Air 4/5", 0.8},
	{1668, 2388, "iPad Pro 11", 0.8},
	{2048, 2732, "iPad Pro 12.9", 0.8},
	{1620, 2160, "iPad 10", 0.8},
	// Laptops
	{2560, 1600, "MacBook Pro 13 / Air", 0.5},
	{2880, 1800, "MacBook Pro 15 (retina)", 0.5},
	{3024, 1964, "MacBook Pro 14", 0.6},
	{3456, 2234, "MacBook Pro 16", 0.6},
	{2560, 1664, "MacBook Air 13 (M2)", 0.6},
	{2880, 1864, "MacBook Air 15", 0.6},
	{3420, 2224, "MacBook Pro 14 (scaled)", 0.6},
	{2736, 1824, "Surface Pro", 0.6},
	{2880, 1920, "Surface Book", 0.6},
	{1366, 768, "budget laptop", 0.35},
	{1280, 800, "small laptop", 0.35},
	{1920, 1200, "16:10 laptop", 0.35},
	// Monitors: weak on their own
	{2560, 1440, "1440p monitor", 0.3},
	{3840, 2160, "4K monitor", 0.3},
	{3440, 1440, "ultrawide monitor", 0.4},
	{5120, 2880, "5K monitor", 0.4},
}

// lookupScreenResolution matches either orientation.
func lookupScreenResolution(w, h int) (screenResolution, bool) {
	for _, r := range commonScreenResolutionList {
		if (r.W == w && r.H == h) || (r.W == h && r.H == w) {
			return r, true
		}
	}
	return screenResolution{}, false
}

// screenshotSoftwareMarkers covers the capture tools that write a Software or
// tEXt tag. The original list had four entries.
var screenshotSoftwareMarkers = []string{
	"snipping tool", "screenclip", "screensketch", "greenshot", "lightshot",
	"screenshot", "sharex", "flameshot", "spectacle", "snagit", "cleanshot",
	"monosnap", "gyazo", "skitch", "gnome-screenshot", "gnome screenshot",
	"ksnapshot", "screencapture", "shutter", "scrot", "maim", "grim",
	"spectrum", "picpick", "faststone capture", "screenpresso",
}

// screenshotFilenameMarkers includes localized names, because a Russian,
// German or Japanese phone does not name its screenshots in English.
var screenshotFilenameMarkers = []string{
	"screenshot", "screen_shot", "screen-shot", "scrshot", "screen capture",
	"screencapture", "scrn",
	"\u0441\u043D\u0438\u043C\u043E\u043A \u044D\u043A\u0440\u0430\u043D\u0430", // снимок экрана
	"\u0441\u043A\u0440\u0438\u043D\u0448\u043E\u0442",                          // скриншот
	"bildschirmfoto",
	"capture d'\u00E9cran",
	"capture d\u2019\u00E9cran",
	"captura de pantalla",
	"schermafbeelding",
	"zrzut ekranu",
	"\u30B9\u30AF\u30EA\u30FC\u30F3\u30B7\u30E7\u30C3\u30C8", // スクリーンショット
	"\u5C4F\u5E55\u5FEB\u7167",                               // 屏幕快照
	"\u622A\u5C4F",                                           // 截屏
	"\uC2A4\uD06C\uB9B0\uC0F7",                               // 스크린샷
	"ekran g\u00F6r\u00FCnt\u00FCs\u00FC",
	"immagine dello schermo",
}

// screenshotSignal is one piece of evidence with a weight and a provenance.
// Source matters: a filename is the single most forgeable signal in the file,
// so a consumer must be able to demand content-only evidence. The old code
// gave the filename the maximum verdict ("Yes") and content evidence a weaker
// one ("Likely") - exactly backwards.
type screenshotSignal struct {
	ID       string
	Weight   float64
	Evidence string
	Source   string // "content" | "filename_hint"
}

type screenshotVerdict struct {
	Score      float64
	Confidence string // "low" | "medium" | "high"
	Signals    []screenshotSignal
}

func (v screenshotVerdict) reason() string {
	if len(v.Signals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v.Signals))
	for _, s := range v.Signals {
		parts = append(parts, s.Evidence)
	}
	label := map[string]string{"high": "Yes", "medium": "Likely", "low": "Possibly"}[v.Confidence]
	return fmt.Sprintf("%s (score %.2f): %s", label, v.Score, strings.Join(parts, "; "))
}

// screenshotInput is everything the heuristic is allowed to look at. It is a
// struct because the old positional signature could not reach the PNG text
// chunks and the JPEG comment that the parser had ALREADY extracted - the
// data was there, the function simply could not see it.
type screenshotInput struct {
	Filename      string
	Format        MediaType
	Width, Height int
	HasDims       bool
	// CaptureEvidence is proof of an actual exposure, which is not the same
	// thing as having a Make/Model: Samsung, and several Xiaomi ROMs, write
	// Make/Model into screenshots, so keying off those disabled the heuristic
	// on one of the largest Android vendors.
	CaptureEvidence int
	Software        []string // EXIF Software, PNG tEXt, XMP CreatorTool, JPEG COM
	UserComment     string
	PNGChunkNames   []string
	PNGDPI          int
	HasICCCamera    bool
}

func detectScreenshotV2(in screenshotInput) screenshotVerdict {
	var v screenshotVerdict
	add := func(id string, weight float64, source, format string, args ...interface{}) {
		v.Signals = append(v.Signals, screenshotSignal{
			ID: id, Weight: weight, Source: source,
			Evidence: fmt.Sprintf(format, args...),
		})
		v.Score += weight
	}

	// filepath.Base: the old code matched against the full path, so every
	// photo inside ~/Pictures/Screenshots/ was labelled a screenshot.
	name := strings.ToLower(filepath.Base(in.Filename))
	for _, m := range screenshotFilenameMarkers {
		if strings.Contains(name, m) {
			add("filename.marker", 0.55, "filename_hint", "filename contains %q", m)
			break
		}
	}

	for _, sw := range in.Software {
		lower := strings.ToLower(sw)
		for _, m := range screenshotSoftwareMarkers {
			if strings.Contains(lower, m) {
				add("software.capture_tool", 0.9, "content", "software tag %q", sw)
				break
			}
		}
	}

	// iOS and macOS write the literal word "Screenshot" into UserComment.
	// This is the strongest single signal a screenshot carries, and the old
	// code hex-dumped it instead of reading it.
	if strings.Contains(strings.ToLower(in.UserComment), "screenshot") {
		add("exif.user_comment", 0.95, "content", "UserComment is %q", in.UserComment)
	}

	// Apple's private iDOT chunk appears in macOS screenshots and essentially
	// nowhere else.
	for _, c := range in.PNGChunkNames {
		switch c {
		case "iDOT":
			add("png.idot_chunk", 0.6, "content", "private Apple iDOT chunk present")
		case "CgBI":
			add("png.cgbi_chunk", 0.4, "content", "iOS CgBI PNG")
		}
	}
	if in.PNGDPI == 144 {
		add("png.phys_144dpi", 0.3, "content", "pHYs reports 144 dpi (macOS retina capture)")
	} else if in.PNGDPI == 96 {
		add("png.phys_96dpi", 0.2, "content", "pHYs reports 96 dpi (Windows capture)")
	}

	if in.HasDims && in.Width > 0 && in.Height > 0 {
		if r, ok := lookupScreenResolution(in.Width, in.Height); ok {
			add("dimensions.known_screen", r.Weight, "content",
				"%dx%d matches %s", in.Width, in.Height, r.Device)
		}
		// A long Android scroll capture keeps the screen width and grows.
		if in.Height > in.Width*2 {
			for _, r := range commonScreenResolutionList {
				if r.W == in.Width && in.Height > r.H {
					add("dimensions.scroll_capture", 0.5, "content",
						"width matches %s but height %d exceeds the panel", r.Device, in.Height)
					break
				}
			}
		}
	}

	// Counter-signals. Two independent optical parameters are hard to fake
	// accidentally and mean an actual exposure happened.
	if in.CaptureEvidence >= 2 {
		add("exif.capture_evidence", -0.8, "content",
			"%d independent capture parameters present", in.CaptureEvidence)
	}
	if in.HasICCCamera {
		add("icc.camera_profile", -0.3, "content", "camera-style ICC profile present")
	}

	switch {
	case v.Score >= 0.9:
		v.Confidence = "high"
	case v.Score >= 0.5:
		v.Confidence = "medium"
	case v.Score > 0.2:
		v.Confidence = "low"
	default:
		v.Signals = nil
		v.Score = 0
	}
	return v
}

// detectScreenshot keeps the original signature for existing callers.
func detectScreenshot(filename string, format MediaType, width, height int, hasDims, hasCameraExif bool, software string) (reason string, isScreenshot bool) {
	evidence := 0
	if hasCameraExif {
		evidence = 2
	}
	v := detectScreenshotV2(screenshotInput{
		Filename: filename, Format: format, Width: width, Height: height,
		HasDims: hasDims, CaptureEvidence: evidence,
		Software: []string{software},
	})
	return v.reason(), v.Confidence != ""
}
