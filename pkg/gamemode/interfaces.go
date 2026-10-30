package gamemode

import (
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CORE GAMEMODE INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatCalculator calculates threat scores for APKs based on patch points
type ThreatCalculator interface {
	CalculateThreatScore(patchPoints []ml.PatchPoint, result *types.AnalysisResult) ThreatResult
	GetCategoryBreakdown(threatResult ThreatResult) []CategoryBreakdown
}

type XPGainBreakdown struct {
	StaticXP   int `json:"static_xp"`
	PatcherXP  int `json:"patcher_xp"`
	FeedbackXP int `json:"feedback_xp"`
}

// XPSystem manages XP and level progression
type XPSystem interface {
	CalculateXP(threatScore float64, complexity int, result *types.AnalysisResult, isStatic bool, isPatcher bool, isFeedback bool) XPGainBreakdown
	AddXP(userID string, breakdown XPGainBreakdown) error
	GetLevel(userID string) int
	GetXPThreshold(level int) int
	GetXPData(userID string) *XPData
	PersistData() error
	LoadData() error
}

// RankSystem assigns ranks based on threat levels
type RankSystem interface {
	AssignRank(threatScore float64) Rank
	GetRankHistory(userID string) []RankHistory
	GetCurrentRank(userID string) Rank
	UpdateRank(userID string, rank Rank) error
}

// OutputFormatter formats analysis results with gamified styling
type OutputFormatter interface {
	FormatResult(result *types.AnalysisResult, gameData *GameData) string
	FormatMarkdown(result *types.AnalysisResult, gameData *GameData) string
	FormatJSON(result *types.AnalysisResult, gameData *GameData) ([]byte, error)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

// ThreatResult contains threat score calculation results
type ThreatResult struct {
	TotalScore        float64             `json:"total_score"`
	ByCategory        map[string]float64  `json:"by_category"`
	CategoryBreakdown []CategoryBreakdown `json:"category_breakdown"`
	DiversityBonus    float64             `json:"diversity_bonus"`
}

// CategoryBreakdown shows threat points by category
type CategoryBreakdown struct {
	Category string  `json:"category"`
	Points   float64 `json:"points"`
	Weight   float64 `json:"weight"`
	Count    int     `json:"count"`
}

// XPData contains XP and level information
type XPData struct {
	TotalXP      int    `json:"total_xp"`
	CurrentLevel int    `json:"current_level"`
	XPThreshold  int    `json:"xp_threshold"`
	LastUpdated  string `json:"last_updated"`

	// 3 XP Systems
	StaticXP        int `json:"static_xp"`
	StaticLevel     int `json:"static_level"`
	StaticThreshold int `json:"static_threshold"`

	PatcherXP        int `json:"patcher_xp"`
	PatcherLevel     int `json:"patcher_level"`
	PatcherThreshold int `json:"patcher_threshold"`

	FeedbackXP        int `json:"feedback_xp"`
	FeedbackLevel     int `json:"feedback_level"`
	FeedbackThreshold int `json:"feedback_threshold"`
}

// RankData contains rank information
type RankData struct {
	CurrentRank Rank          `json:"current_rank"`
	RankHistory []RankHistory `json:"rank_history"`
	HighestRank Rank          `json:"highest_rank"`
}

// Rank represents a player rank
type Rank struct {
	ID          int     `json:"id"`
	Title       string  `json:"title"`
	Emoji       string  `json:"emoji"`
	MinThreat   float64 `json:"min_threat"`
	Description string  `json:"description"`
}

// RankHistory tracks rank progression
type RankHistory struct {
	Rank      Rank   `json:"rank"`
	Timestamp string `json:"timestamp"`
	APKName   string `json:"apk_name"`
}

// GameData contains all game mode data for an analysis
type GameData struct {
	ThreatResult      *ThreatResult   `json:"threat_result"`
	XPData            *XPData         `json:"xp_data"`
	RankData          *RankData       `json:"rank_data"`
	XPGained          int             `json:"xp_gained"`
	XPGainedBreakdown XPGainBreakdown `json:"xp_gained_breakdown"`
	UnlockedBadges    []BadgeID       `json:"unlocked_badges,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// RANK DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

var DefaultRanks = []Rank{
	{ID: 1, Title: "Novice", Emoji: "🔰", MinThreat: 0, Description: "Just getting started"},
	{ID: 2, Title: "Script Kiddie", Emoji: "👶", MinThreat: 50, Description: "Learning the basics"},
	{ID: 3, Title: "Code Explorer", Emoji: "🔍", MinThreat: 100, Description: "Exploring code patterns"},
	{ID: 4, Title: "Bug Hunter", Emoji: "🐛", MinThreat: 200, Description: "Finding vulnerabilities"},
	{ID: 5, Title: "Threat Analyst", Emoji: "🕵️", MinThreat: 300, Description: "Analyzing security threats"},
	{ID: 6, Title: "Security Expert", Emoji: "🛡️", MinThreat: 400, Description: "Expert in security analysis"},
	{ID: 7, Title: "Malware Hunter", Emoji: "🎯", MinThreat: 500, Description: "Hunting malicious code"},
	{ID: 8, Title: "Boss Malware", Emoji: "🔥", MinThreat: 700, Description: "Master of malware analysis"},
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEVEL THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════════

var DefaultLevelThresholds = []int{
	0,    // Level 1
	100,  // Level 2
	250,  // Level 3
	450,  // Level 4
	700,  // Level 5
	1000, // Level 6
	1400, // Level 7
	1850, // Level 8
	2350, // Level 9
	2900, // Level 10
	3500, // Level 11
	4150, // Level 12
	4850, // Level 13
	5600, // Level 14
	6400, // Level 15
}
