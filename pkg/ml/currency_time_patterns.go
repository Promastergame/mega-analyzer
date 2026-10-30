package ml

// ═══════════════════════════════════════════════════════════════════════════════
// CURRENCY AND TIME-BASED RESTRICTION PATTERNS
//
// Patterns for in-game currency manipulation and time-based restrictions
// Requirements: 7.1-7.8, 8.1-8.6
// Task 9: Add in-game currency and time-based restriction patterns
// ═══════════════════════════════════════════════════════════════════════════════

// CurrencyTimePatterns — In-game currency and time-based restriction patterns
var CurrencyTimePatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #1 — Currency Getter Patterns (Task 9.1)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CURRENCY_GETTER",
		Category:    PatchCatPremium,
		Description: "Gets in-game currency/coins amount (getCoins, getGems, getDiamonds, getGold, getCurrency)",
		MethodNames: []string{
			"getcoins", "getgems", "getdiamonds", "getgold", "getcurrency",
			"getbalance", "getcredits", "getstars", "getpoints",
			"getmoney", "getcash", "getsilver", "getcrystals",
			"getruby", "getrubies", "gettokens", "getbucks",
		},
		ClassPatterns: []string{
			"currency", "wallet", "inventory", "economy",
			"bank", "coins", "gems", "money", "balance",
		},
		RequiredCalls: []string{
			"getint", "getlong", "getsharedpreferences",
		},
		StringPatterns: []string{
			"coins", "gems", "diamonds", "gold", "currency",
			"balance", "credits", "stars", "money",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt, // Return max int for unlimited currency
		Weight:        1.1,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #2 — Currency Setter Patterns (Task 9.2)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CURRENCY_SETTER",
		Category:    PatchCatPremium,
		Description: "Sets in-game currency amount (setCoins, addCoins, deductCoins)",
		MethodNames: []string{
			"setcoins", "setgems", "setdiamonds", "setgold", "setcurrency",
			"addcoins", "addgems", "adddiamonds", "addgold",
			"deductcoins", "deductgems", "removecoins", "spendcoins",
			"updatebalance", "setbalance", "savebalance",
		},
		ClassPatterns: []string{
			"currency", "wallet", "inventory", "economy",
			"bank", "coins", "gems", "money", "balance",
		},
		RequiredCalls: []string{
			"putint", "putlong", "edit", "apply", "commit",
			"getsharedpreferences",
		},
		StringPatterns: []string{
			"coins", "gems", "diamonds", "gold", "currency",
			"balance", "credits", "stars", "money",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.6,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #3 — Currency Validation Patterns (Task 9.3)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CURRENCY_VALIDATION",
		Category:    PatchCatTamper,
		Description: "Currency tampering validation checks",
		MethodNames: []string{
			"validatecurrency", "checkcurrencytamper", "verifycurrency",
			"iscurrencyvalid", "checkcurrencyintegrity",
			"validatebalance", "checkbalancetamper",
		},
		ClassPatterns: []string{
			"currency", "wallet", "validation", "integrity",
			"tamper", "security",
		},
		RequiredCalls: []string{
			"getint", "getlong", "messagedigest",
			"getsharedpreferences",
		},
		StringPatterns: []string{
			"currency", "balance", "tamper", "integrity",
			"checksum", "hash", "validation",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #4 — Currency Transaction Patterns (Task 9.4)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CURRENCY_TRANSACTION",
		Category:    PatchCatPremium,
		Description: "Currency transaction methods (purchase, spend, earn)",
		MethodNames: []string{
			"purchasewithcoins", "spendcoins", "earncoins",
			"buywithgems", "spendgems", "earngems",
			"deductcurrency", "addcurrency", "rewardcurrency",
			"processtransaction", "executepurchase",
		},
		ClassPatterns: []string{
			"currency", "transaction", "purchase", "shop",
			"store", "economy", "wallet",
		},
		RequiredCalls: []string{
			"getint", "putint", "edit", "apply",
		},
		StringPatterns: []string{
			"purchase", "spend", "earn", "transaction",
			"buy", "cost", "price",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.7,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #5 — Energy/Lives System Patterns (Task 9.5)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ENERGY_LIVES_SYSTEM",
		Category:    PatchCatPremium,
		Description: "Energy/lives system methods (getEnergy, getLives, hasEnergy)",
		MethodNames: []string{
			"getenergy", "getlives", "gethearts", "getstamina",
			"hasenergy", "haslives", "hashearts",
			"setenergy", "setlives", "addenergy", "addlives",
			"deductenergy", "deductlives", "consumeenergy",
		},
		ClassPatterns: []string{
			"energy", "lives", "hearts", "stamina",
			"health", "gameplay", "player",
		},
		RequiredCalls: []string{
			"getint", "putint", "getsharedpreferences",
		},
		StringPatterns: []string{
			"energy", "lives", "hearts", "stamina",
			"health", "life", "hp",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt, // Return max for unlimited energy/lives
		Weight:        1.0,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// CURRENCY #6 — Currency Balance Check Patterns (Task 9.6)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CURRENCY_BALANCE_CHECK",
		Category:    PatchCatPremium,
		Description: "Currency balance check methods (hasEnoughCoins, canAfford)",
		MethodNames: []string{
			"hasenoughcoins", "hasenoughgems", "hasenoughcurrency",
			"canafford", "canpurchase", "canbuy",
			"isenough", "hassufficientfunds", "hasbalance",
			"checkbalance", "verifybalance",
		},
		ClassPatterns: []string{
			"currency", "wallet", "purchase", "shop",
			"economy", "balance",
		},
		RequiredCalls: []string{
			"getint", "getlong",
		},
		StringPatterns: []string{
			"enough", "afford", "sufficient", "balance",
			"funds", "cost", "price",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.7,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// TIME #1 — Cooldown Timer Check (Task 9.7)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "COOLDOWN_TIMER_CHECK",
		Category:    PatchCatTrialExpiry,
		Description: "Cooldown timer check methods",
		MethodNames: []string{
			"iscooldownactive", "hascooldown", "checkcooldown",
			"getcooldowntime", "iscooldownfinished",
			"canuse", "isavailable", "isready",
			"getremainingcooldown", "cooldownremaining",
		},
		ClassPatterns: []string{
			"cooldown", "timer", "time", "delay",
			"wait", "gameplay",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"getlong", "getsharedpreferences",
		},
		StringPatterns: []string{
			"cooldown", "timer", "last_use", "next_available",
			"wait_time", "delay",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse, // No cooldown active
		Weight:        0.7,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// TIME #2 — Energy Regeneration Time (Task 9.7)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ENERGY_REGENERATION_TIME",
		Category:    PatchCatTrialExpiry,
		Description: "Energy regeneration time calculation",
		MethodNames: []string{
			"getenergyregentime", "calculateenergyregeneration",
			"getnextenergyrefill", "energyrefilltime",
			"getregenerationtime", "gettimeuntilrefill",
			"calculaterefilltime",
		},
		ClassPatterns: []string{
			"energy", "regeneration", "refill", "timer",
			"gameplay",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"getlong", "getint",
		},
		StringPatterns: []string{
			"energy", "regeneration", "refill", "regen",
			"restore", "recharge",
		},
		ReturnType:    "J",
		PatchType:     PatchReturnMaxInt, // Instant regeneration
		Weight:        0.6,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// TIME #3 — Daily Limit Check (Task 9.7)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "DAILY_LIMIT_CHECK",
		Category:    PatchCatTrialExpiry,
		Description: "Daily limit check methods",
		MethodNames: []string{
			"hasdailylimit", "isdailylimitreached", "checkdailylimit",
			"getdailylimit", "getdailyusage", "canusedaily",
			"isdailyavailable", "resetdailylimit",
		},
		ClassPatterns: []string{
			"daily", "limit", "usage", "quota",
			"restriction",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"calendar;->getinstance",
			"getint", "getlong", "getsharedpreferences",
		},
		StringPatterns: []string{
			"daily", "limit", "quota", "usage",
			"per_day", "daily_limit", "max_daily",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse, // No limit reached
		Weight:        0.7,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// TIME #4 — Time-Gated Content Availability (Task 9.7)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "TIME_GATED_CONTENT",
		Category:    PatchCatTrialExpiry,
		Description: "Time-gated content availability check",
		MethodNames: []string{
			"iscontentavailable", "isunlocked", "canaccess",
			"istimegated", "checkavailability",
			"isavailablenow", "getunlocktime",
		},
		ClassPatterns: []string{
			"content", "unlock", "timegate", "availability",
			"access", "level",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"getlong", "getboolean",
		},
		StringPatterns: []string{
			"unlock", "available", "timegate", "access",
			"unlock_time", "available_at",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue, // Always available
		Weight:        0.7,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// TIME #5 — Last Action Timestamp Validation (Task 9.7)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "LAST_ACTION_TIMESTAMP",
		Category:    PatchCatTrialExpiry,
		Description: "Last action timestamp validation",
		MethodNames: []string{
			"getlastactiontime", "savelastactiontime",
			"updatelastaction", "checklastaction",
			"getlastupdatetime", "setlastupdatetime",
			"validatetimestamp",
		},
		ClassPatterns: []string{
			"timestamp", "lastaction", "time", "action",
			"update",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"getlong", "putlong", "getsharedpreferences",
		},
		StringPatterns: []string{
			"last_action", "last_update", "timestamp",
			"last_time", "last_used",
		},
		ReturnType:    "J",
		PatchType:     PatchReturnMaxInt,
		Weight:        0.6,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// GAME ECONOMY — EXPANDED DETECTIONS (v2)
	// Больше игровой экономики: hard/soft currency, ресурсы, «безлимит»,
	// affordability, unlock/owned, цены, VIP/battle-pass, daily reward, гача.
	// ═══════════════════════════════════════════════════════════════════════

	// HARD CURRENCY (премиальная валюта) — gems/crystals/diamonds/…
	{
		ID:          "HARD_CURRENCY_GETTER",
		Category:    PatchCatCurrency,
		Description: "Gets premium/hard currency (gems, crystals, diamonds, rubies, emeralds, jewels, shards)",
		MethodNames: []string{
			"getgems", "getgem", "getcrystals", "getcrystal", "getdiamonds",
			"getdiamond", "getrubies", "getruby", "getemeralds", "getjewels",
			"getshards", "getshard", "getorbs", "getessence", "getstardust",
			"getpremiumcurrency", "gethardcurrency", "getpaidcurrency",
		},
		ClassPatterns: []string{
			"currency", "wallet", "economy", "shop", "store", "premium",
			"gem", "crystal", "diamond", "inventory", "resource",
		},
		StringPatterns: []string{
			"gems", "crystals", "diamonds", "rubies", "emeralds", "jewels",
			"shards", "premium_currency", "hard_currency",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt,
		Weight:        1.15,
		MinMatchScore: 10,
	},

	// SPECIAL RESOURCES — tickets/tokens/keys/spins/fragments…
	{
		ID:          "SPECIAL_RESOURCE_GETTER",
		Category:    PatchCatCurrency,
		Description: "Gets special resources (tickets, tokens, keys, spins, fragments, scrolls, boosters)",
		MethodNames: []string{
			"gettickets", "gettokens", "getkeys", "getspins", "getfreespins",
			"getfragments", "getscrolls", "getboosters", "getbooster",
			"gethints", "getrefills", "getchestkeys", "getlootboxkeys",
			"getrollcount", "getgachatickets", "getpasses", "getsummons",
		},
		ClassPatterns: []string{
			"resource", "inventory", "shop", "gacha", "lootbox", "reward",
			"wheel", "spin", "chest", "ticket",
		},
		StringPatterns: []string{
			"tickets", "tokens", "spins", "fragments", "boosters",
			"free_spins", "chest_keys", "gacha",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt,
		Weight:        1.05,
		MinMatchScore: 10,
	},

	// AFFORDABILITY — canAfford/hasEnough/canBuy → всегда «да»
	{
		ID:          "AFFORDABILITY_CHECK",
		Category:    PatchCatCurrency,
		Description: "Affordability / enough-currency check (canAfford, hasEnough, canBuy, canPurchase)",
		MethodNames: []string{
			"canafford", "hasenough", "hasenoughcoins", "hasenoughgems",
			"hasenoughcurrency", "hasenoughbalance", "hasenoughmoney",
			"canbuy", "canpurchase", "canspend", "isaffordable", "affordable",
			"cancheckout", "hassufficientfunds", "enoughcurrency",
		},
		ClassPatterns: []string{
			"shop", "store", "purchase", "checkout", "currency", "wallet", "economy",
		},
		StringPatterns: []string{
			"afford", "enough", "insufficient", "not_enough", "balance",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.2,
		MinMatchScore: 10,
	},

	// ITEM UNLOCK / OWNERSHIP — isUnlocked/isOwned/isPurchased → «да»
	{
		ID:          "ITEM_UNLOCK_CHECK",
		Category:    PatchCatFeatureGate,
		Description: "Item/level unlock & ownership check (isUnlocked, isOwned, isPurchased, hasItem)",
		MethodNames: []string{
			"isunlocked", "isitemunlocked", "islevelunlocked", "isstageunlocked",
			"ischaracterunlocked", "isskinunlocked", "isunlock", "unlocked",
			"isowned", "ownsitem", "isbought", "ispurchased", "hasitem",
			"hasitemunlocked", "isavailable", "isredeemed", "isacquired",
			"iscontentunlocked", "hasaccess", "hasunlocked",
		},
		ClassPatterns: []string{
			"unlock", "inventory", "shop", "store", "item", "content",
			"level", "stage", "character", "skin", "catalog",
		},
		StringPatterns: []string{
			"unlocked", "owned", "purchased", "is_unlocked", "has_item",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.15,
		MinMatchScore: 10,
	},

	// ITEM PRICE / COST — getPrice/getCost → 0 (бесплатно)
	{
		ID:          "ITEM_PRICE_GETTER",
		Category:    PatchCatCurrency,
		Description: "Item price/cost getter — patch to 0 to make purchases free (getPrice, getCost, getGemCost)",
		MethodNames: []string{
			"getprice", "getcost", "getitemprice", "getitemcost",
			"getcoincost", "getgemcost", "getpriceincoins", "getpriceingems",
			"getamountrequired", "getrequiredcoins", "getrequiredgems",
			"getunlockcost", "getupgradecost", "getpurchaseprice",
		},
		ClassPatterns: []string{
			"shop", "store", "item", "price", "cost", "purchase", "upgrade",
		},
		StringPatterns: []string{
			"price", "cost", "required", "amount",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnFalse, // const 0 → цена = 0
		Weight:        1.0,
		MinMatchScore: 10,
	},

	// UNLIMITED / INFINITE flags
	{
		ID:          "UNLIMITED_RESOURCE_FLAG",
		Category:    PatchCatFeatureGate,
		Description: "Unlimited/infinite resources flag (isUnlimited, hasInfinite, freeShopping)",
		MethodNames: []string{
			"isunlimited", "hasunlimited", "hasinfinite", "isinfinite",
			"unlimitedmode", "isfreeshopping", "freeshopping",
			"isnolimit", "hasnolimit", "isgodmode", "godmode",
		},
		ClassPatterns: []string{
			"cheat", "mod", "unlimited", "shop", "economy", "resource",
		},
		StringPatterns: []string{
			"unlimited", "infinite", "free_shopping", "no_limit", "godmode",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.1,
		MinMatchScore: 10,
	},

	// STAMINA / FUEL / MOVES / HEARTS — casual-игры
	{
		ID:          "STAMINA_MOVES_GETTER",
		Category:    PatchCatCurrency,
		Description: "Stamina/fuel/moves/hearts getter — max out for infinite play",
		MethodNames: []string{
			"getstamina", "getfuel", "getmoves", "getremainingmoves",
			"gethearts", "getboosters", "getpowerups", "getcontinues",
			"getretries", "getturns", "getactions", "getactionpoints",
		},
		ClassPatterns: []string{
			"stamina", "energy", "fuel", "moves", "hearts", "level", "board", "game",
		},
		StringPatterns: []string{
			"stamina", "fuel", "moves", "hearts", "boosters", "continues",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt,
		Weight:        1.0,
		MinMatchScore: 10,
	},

	// STAMINA has-check → «да»
	{
		ID:          "RESOURCE_HAS_CHECK",
		Category:    PatchCatFeatureGate,
		Description: "Resource availability check (hasStamina, hasMoves, hasHearts, hasBoosters)",
		MethodNames: []string{
			"hasstamina", "hasmoves", "hashearts", "hasboosters", "hasfuel",
			"hasspins", "hasenergy", "hasturns", "hascontinues", "hasretries",
			"canplay", "cancontinue", "canspin", "canmove",
		},
		ClassPatterns: []string{
			"stamina", "energy", "moves", "hearts", "game", "level",
		},
		StringPatterns: []string{
			"stamina", "moves", "hearts", "energy", "spins",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.05,
		MinMatchScore: 10,
	},

	// AD-FREE entitlement
	{
		ID:          "AD_FREE_ENTITLEMENT",
		Category:    PatchCatAds,
		Description: "Ad-free entitlement check (isAdFree, isNoAds, adsRemoved) — grant it",
		MethodNames: []string{
			"isadfree", "isadsfree", "isadremoved", "isadsremoved", "adsremoved",
			"isnoads", "isnoad", "hasremovedads", "hasnoads", "isadsdisabled",
			"ispremiumnoads", "isadfreeuser", "hasadfree",
		},
		ClassPatterns: []string{
			"ads", "ad", "premium", "billing", "iap", "purchase",
		},
		StringPatterns: []string{
			"ad_free", "no_ads", "remove_ads", "ads_removed", "adfree",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.15,
		MinMatchScore: 10,
	},

	// VIP / BATTLE PASS / SEASON PASS
	{
		ID:          "VIP_BATTLEPASS_CHECK",
		Category:    PatchCatSubscription,
		Description: "VIP / battle-pass / season-pass ownership (isVip, hasBattlePass, isPassActive)",
		MethodNames: []string{
			"isvip", "isvipactive", "isvipmember", "hasvipaccess", "hasvip",
			"isbattlepassowned", "hasbattlepass", "ispassactive", "ispremiumpass",
			"isseasonpassowned", "hasseasonpass", "ispassowned", "iselite",
			"isgoldmember", "isplusmember", "haspremiumpass",
		},
		ClassPatterns: []string{
			"vip", "battlepass", "seasonpass", "pass", "membership", "premium", "subscription",
		},
		StringPatterns: []string{
			"vip", "battle_pass", "season_pass", "battlepass", "elite", "gold_member",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.15,
		MinMatchScore: 10,
	},

	// DAILY REWARD / CLAIM
	{
		ID:          "DAILY_REWARD_CLAIM",
		Category:    PatchCatFeatureGate,
		Description: "Daily reward / claim availability (canClaim, isRewardAvailable, canCollect)",
		MethodNames: []string{
			"canclaim", "canclaimreward", "canclaimdaily", "isrewardavailable",
			"isdailyavailable", "cancollect", "cancollectreward", "isclaimable",
			"canredeem", "isbonusavailable", "cangetdaily", "candailyreward",
		},
		ClassPatterns: []string{
			"reward", "daily", "claim", "bonus", "gift", "collect",
		},
		StringPatterns: []string{
			"daily", "reward", "claim", "bonus", "collect",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.0,
		MinMatchScore: 10,
	},

	// SHOP PURCHASE RESULT — buyItem/purchaseItem → success
	{
		ID:          "SHOP_PURCHASE_RESULT",
		Category:    PatchCatBilling,
		Description: "In-game shop purchase result (buyItem, purchaseItem, completePurchase) → success",
		MethodNames: []string{
			"buyitem", "purchaseitem", "completepurchase", "onpurchasesuccess",
			"processpurchase", "confirmpurchase", "dobuy", "trybuy", "buysucceeded",
			"ispurchasesuccessful", "ispurchasevalid", "purchasesucceeded",
		},
		ClassPatterns: []string{
			"shop", "store", "purchase", "checkout", "iap", "billing",
		},
		StringPatterns: []string{
			"purchase", "buy", "checkout", "transaction",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.1,
		MinMatchScore: 10,
	},
}

// GetAllCurrencyTimePatterns returns all currency and time-based restriction patterns
func GetAllCurrencyTimePatterns() []VulnerablePattern {
	return CurrencyTimePatterns
}
