package gamemode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type BadgeID string

const (
	BadgeFirstBlood   BadgeID = "first_blood"
	BadgeComboMaster  BadgeID = "combo_master"
	BadgeUntouchable  BadgeID = "untouchable"
	BadgeBossSlayer   BadgeID = "boss_slayer"
	BadgePatchSurgeon BadgeID = "patch_surgeon"
	BadgeWeekStreak   BadgeID = "week_streak"
	BadgeMonthStreak  BadgeID = "month_streak"
	BadgeCategoryKing BadgeID = "category_king"
	BadgeFeedbackGuru BadgeID = "feedback_guru"
	BadgeRankUp       BadgeID = "rank_up"
	BadgeMaxRank      BadgeID = "max_rank"
	BadgePrestige1    BadgeID = "prestige_1"
	BadgeCenturion    BadgeID = "centurion"
)

type BadgeMeta struct {
	ID          BadgeID
	Title       string
	Emoji       string
	Description string
	Rarity      string
}

var BadgeCatalog = map[BadgeID]BadgeMeta{
	BadgeFirstBlood:   {BadgeFirstBlood, "First Blood", "🩸", "Complete your first analysis", "common"},
	BadgeComboMaster:  {BadgeComboMaster, "Combo Master", "⚡", "Detect 10+ threats in a single run", "uncommon"},
	BadgeUntouchable:  {BadgeUntouchable, "Untouchable", "🧊", "Threat score below 10 (clean APK)", "uncommon"},
	BadgeBossSlayer:   {BadgeBossSlayer, "Boss Slayer", "💀", "Threat score >= 900 in a single run", "rare"},
	BadgePatchSurgeon: {BadgePatchSurgeon, "Patch Surgeon", "🔧", "Complete 50 patcher-mode analyses", "rare"},
	BadgeWeekStreak:   {BadgeWeekStreak, "Week Warrior", "🔥", "Run analyses 7 days in a row", "uncommon"},
	BadgeMonthStreak:  {BadgeMonthStreak, "Relentless", "🌋", "Run analyses 30 days in a row", "legendary"},
	BadgeCategoryKing: {BadgeCategoryKing, "Category King", "👑", "Hit 5+ threat categories in one run", "rare"},
	BadgeFeedbackGuru: {BadgeFeedbackGuru, "Feedback Guru", "🧠", "Submit 20 ML feedback sessions", "uncommon"},
	BadgeRankUp:       {BadgeRankUp, "Promoted", "📈", "Earn your first rank promotion", "common"},
	BadgeMaxRank:      {BadgeMaxRank, "Top Dog", "🏆", "Reach the highest rank tier", "legendary"},
	BadgePrestige1:    {BadgePrestige1, "Prestige I", "✨", "Complete your first prestige rebirth", "legendary"},
	BadgeCenturion:    {BadgeCenturion, "Centurion", "🛡️", "Complete 100 analyses", "rare"},
}

type EarnedBadge struct {
	ID       BadgeID `json:"id"`
	EarnedAt string  `json:"earned_at"`
	APKName  string  `json:"apk_name,omitempty"`
	RunScore float64 `json:"run_score,omitempty"`
}

type BadgeData struct {
	Earned        []EarnedBadge `json:"earned"`
	TotalAnalyses int           `json:"total_analyses"`
	PatcherRuns   int           `json:"patcher_runs"`
	FeedbackRuns  int           `json:"feedback_runs"`
}

type BadgeSystem struct {
	dataFile string
	userData map[string]*BadgeData
}

func NewBadgeSystem() *BadgeSystem {
	dataFile := gamemodeDataFile("badge_data.json")
	bs := &BadgeSystem{
		dataFile: dataFile,
		userData: make(map[string]*BadgeData),
	}
	_ = bs.LoadData()
	return bs
}

type EvalContext struct {
	UserID          string
	APKName         string
	ThreatScore     float64
	PatchPointCount int
	UniqueCats      int
	IsStatic        bool
	IsPatcher       bool
	IsFeedback      bool
	RankPromoted    bool
	ReachedMaxRank  bool
	Prestiged       bool
	CurrentStreak   int
}

func (bs *BadgeSystem) EvalBadges(ctx EvalContext) ([]BadgeID, error) {
	data := bs.ensureUser(ctx.UserID)
	data.TotalAnalyses++
	if ctx.IsPatcher {
		data.PatcherRuns++
	}
	if ctx.IsFeedback {
		data.FeedbackRuns++
	}

	var newlyUnlocked []EarnedBadge
	check := func(id BadgeID, cond bool) {
		if cond && !bs.hasEarned(data, id) {
			newlyUnlocked = append(newlyUnlocked, EarnedBadge{
				ID:       id,
				EarnedAt: time.Now().Format(time.RFC3339),
				APKName:  ctx.APKName,
				RunScore: ctx.ThreatScore,
			})
		}
	}

	check(BadgeFirstBlood, data.TotalAnalyses == 1)
	check(BadgeComboMaster, ctx.PatchPointCount >= 10)
	check(BadgeUntouchable, ctx.ThreatScore < 10)
	check(BadgeBossSlayer, ctx.ThreatScore >= 900)
	check(BadgePatchSurgeon, data.PatcherRuns >= 50)
	check(BadgeCategoryKing, ctx.UniqueCats >= 5)
	check(BadgeFeedbackGuru, data.FeedbackRuns >= 20)
	check(BadgeRankUp, ctx.RankPromoted)
	check(BadgeMaxRank, ctx.ReachedMaxRank)
	check(BadgePrestige1, ctx.Prestiged)
	check(BadgeWeekStreak, ctx.CurrentStreak >= 7)
	check(BadgeMonthStreak, ctx.CurrentStreak >= 30)
	check(BadgeCenturion, data.TotalAnalyses >= 100)

	data.Earned = append(data.Earned, newlyUnlocked...)
	if err := bs.PersistData(); err != nil {
		return nil, err
	}

	ids := make([]BadgeID, len(newlyUnlocked))
	for i, b := range newlyUnlocked {
		ids[i] = b.ID
	}
	return ids, nil
}

func (bs *BadgeSystem) hasEarned(data *BadgeData, id BadgeID) bool {
	for _, e := range data.Earned {
		if e.ID == id {
			return true
		}
	}
	return false
}

func (bs *BadgeSystem) GetEarned(userID string) []EarnedBadge {
	if d, ok := bs.userData[userID]; ok {
		return d.Earned
	}
	return nil
}

func (bs *BadgeSystem) ensureUser(userID string) *BadgeData {
	if bs.userData[userID] == nil {
		bs.userData[userID] = &BadgeData{}
	}
	return bs.userData[userID]
}

func (bs *BadgeSystem) PersistData() error {
	dir := filepath.Dir(bs.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(bs.userData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bs.dataFile, data, 0644)
}

func (bs *BadgeSystem) LoadData() error {
	raw, err := os.ReadFile(bs.dataFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &bs.userData)
}
