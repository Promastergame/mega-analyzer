package ml

import (
	"testing"
)

// Sanity для SmaliValidator на инлайн-фикстурах (без внешних файлов).
// Раньше тест читал ../../ml_test/*.smali, которой нет в репо — падал с
// "system cannot find the path specified" на любой машине.
func TestZzMlTestFixturesSanity(t *testing.T) {
	valid := map[string]string{
		"zzcheck_numeric_offsets": ".method public static getCoins()I\n" +
			"    .registers 2\n" +
			"    const/4 v0, 0x1\n" +
			"    return v0\n" +
			".end method",
		"checksecurity_dual_return": ".method public static checkRoot()Z\n" +
			"    .registers 2\n" +
			"    const/4 v0, 0x0\n" +
			"    return v0\n" +
			".end method",
		"getcoins_wallet": ".method public getCoins()I\n" +
			"    .registers 2\n" +
			"    const/4 v0, 0x1\n" +
			"    return v0\n" +
			".end method",
	}
	invalid := map[string]string{
		"emulator_F_broken": ".method public static F()I\n" +
			"    .registers 2\n" +
			"    const-string v4, \"Emulator\"\n" +
			"    return v0\n" +
			".end method",
		"v16_narrow_invalid": ".method public static t()V\n" +
			"    .registers 2\n" +
			"    const/16 v300, 0x1\n" +
			"    return-void\n" +
			".end method",
		"p2_overflow_invalid": ".method public static t()Z\n" +
			"    .registers 2\n" +
			"    const/4 v0, 0x8\n" +
			"    return v0\n" +
			".end method",
	}
	v := NewSmaliValidator()
	for name, smali := range valid {
		if res := v.ValidateStrict(smali); !res.Valid {
			t.Errorf("%s should be VALID, got %v", name, res.Errors)
		}
	}
	for name, smali := range invalid {
		if res := v.ValidateStrict(smali); res.Valid {
			t.Errorf("%s should be INVALID", name)
		}
	}
}
