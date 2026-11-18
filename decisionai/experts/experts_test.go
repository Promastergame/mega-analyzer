package experts

import (
	"encoding/json"
	"os"
	"testing"

	"decisionai/client"
	"decisionai/s1"
	"decisionai/smalirole"
)

func engine(t *testing.T) *s1.Engine {
	t.Helper()
	var role *smalirole.Model
	if _, err := os.Stat("../models/smalirole-model.json"); err == nil {
		m, err := smalirole.LoadModel("../models/smalirole-model.json")
		if err != nil {
			t.Fatal(err)
		}
		role = m
	}
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(role, nil)
	return e
}

func roleModel(e *s1.Engine) *smalirole.Model {
	for _, expert := range e.Experts {
		if role, ok := expert.(Role); ok {
			return role.Model
		}
	}
	return nil
}

func decide(t *testing.T, e *s1.Engine, req string) s1.Response {
	t.Helper()
	var r s1.Request
	if err := json.Unmarshal([]byte(req), &r); err != nil {
		t.Fatal(err)
	}
	resp, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

const effectQ = `"effect":{"type":"noul","instructions":"Подтверждён ли нужный эффект патча?","criteria":{"true":"Эффект наблюдался на текущей сборке","false":"Эффект не наблюдался"}}`

func TestChecksRule(t *testing.T) {
	e := engine(t)
	cases := []struct {
		state string
		want  float64
		route string
	}{
		{`{"build":{"status":"pass","sha256_matches":true},"runtime":{"status":"pass"},"effect_verified":true}`, 0.98, "auto"},
		{`{"build":{"status":"pass","sha256_matches":true},"runtime":{"status":"pass"},"notes":"лимит стал 1000"}`, 0.85, "review"},
		{`{"build":{"status":"fail"},"runtime":{"status":"pass"}}`, 0.02, "auto"},
		{`{"build":"pass","runtime":"not_run"}`, 0.02, "auto"},
		{`{"build":"pass","runtime":"pass","sha256_matches":false}`, 0.02, "auto"},
	}
	for _, c := range cases {
		a := decide(t, e, `{"state":`+c.state+`,"questions":{`+effectQ+`}}`).Answers["effect"]
		if a.Source != "checks-rule" || *a.Noul != c.want || a.Route != c.route {
			t.Errorf("%s → %s %v %s", c.state, a.Source, *a.Noul, a.Route)
		}
	}
	// free text only: the rule must stay silent
	a := decide(t, e, `{"state":"Сборка прошла","questions":{`+effectQ+`}}`).Answers["effect"]
	if a.Source == "checks-rule" {
		t.Error("checks-rule answered free text")
	}
}

func TestServerRule(t *testing.T) {
	e := engine(t)
	q := `"server":{"type":"score","instructions":"Насколько поведение зависит от сервера?","criteria":{"0":"Полностью локально","1":"Есть кэш с сервера","2":"Сервер проверяет значение","3":"Значение решает сервер"}}`
	for state, want := range map[string]string{
		`"Сетевых запросов при проверке не было."`:                       "0",
		`"Сервер проверяет количество монет при каждой покупке."`:        "2",
		`"Награда рассчитывается на сервере, клиент только отображает."`: "3",
		`{"server_dependency":"local_only"}`: "0",
	} {
		a := decide(t, e, `{"state":`+state+`,"questions":{`+q+`}}`).Answers["server"]
		best := a.Probabilities[0]
		for _, kv := range a.Probabilities {
			if kv.P > best.P {
				best = kv
			}
		}
		if a.Source != "server-rule" || best.Key != want {
			t.Errorf("%s → %s %s", state, a.Source, best.Key)
		}
	}
}

func TestRoleExpert(t *testing.T) {
	e := engine(t)
	if roleModel(e) == nil {
		t.Skip("no smalirole model")
	}
	q := `"role":{"type":"choice","instructions":"Какую роль играет изменённый литерал?","criteria":{"limit":"Лимит или максимум значения","delay":"Задержка или таймер","color":"Цвет","resource_id":"Идентификатор ресурса","other":null}}`
	// full method body → trained model (+ method-name rule)
	code, _ := json.Marshal(".method public getMaxCoins()I\n    .registers 2\n    const/16 v0, 0x64\n    return v0\n.end method")
	a := decide(t, e, `{"state":{"code":`+string(code)+`},"questions":{`+q+`}}`).Answers["role"]
	if a.Source != "smalirole" || a.Choice != "limit" {
		t.Errorf("code: %s %s %v", a.Source, a.Choice, a.Probabilities)
	}
	// typed sink, no name hint: the model alone
	code, _ = json.Marshal(".method public run(Landroid/os/Handler;Ljava/lang/Runnable;)V\n    .registers 5\n    const-wide/16 v0, 0x1f4\n    invoke-virtual {p1, p2, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\n    return-void\n.end method")
	a = decide(t, e, `{"state":{"code":`+string(code)+`},"questions":{`+q+`}}`).Answers["role"]
	if a.Source != "smalirole" || a.Choice != "delay" {
		t.Errorf("postDelayed: %s %s %v", a.Source, a.Choice, a.Probabilities)
	}
	// only a description with the method name
	a = decide(t, e, `{"state":{"candidate":"getMaxCoins() const/16 v0, 0x64 → 0x3e8"},"questions":{`+q+`}}`).Answers["role"]
	if a.Source != "smalirole" || a.Choice != "limit" || a.Route == "auto" {
		t.Errorf("snippet: %s %s %s", a.Source, a.Choice, a.Route)
	}
	// options that are not literal roles: expert must not answer
	q2 := `"role":{"type":"choice","instructions":"Какую роль играет пользователь?","criteria":{"admin":"Администратор","guest":"Гость"}}`
	if a := decide(t, e, `{"state":{"code":`+string(code)+`},"questions":{`+q2+`}}`).Answers["role"]; a.Source == "smalirole" {
		t.Error("role expert answered an unrelated question")
	}
}

func TestOnlyDeclaredKeys(t *testing.T) {
	e := engine(t)
	q := `"role":{"type":"choice","instructions":"Роль литерала?","criteria":{"limit":"лимит","delay":"задержка"}}`
	a := decide(t, e, `{"state":{"candidate":"getMaxCoins() const/16 v0, 0x64"},"questions":{`+q+`}}`).Answers["role"]
	sum := 0.0
	for _, kv := range a.Probabilities {
		if kv.Key != "limit" && kv.Key != "delay" {
			t.Fatal("undeclared key", kv.Key)
		}
		sum += kv.P
	}
	if sum < 0.999 || sum > 1.001 {
		t.Fatal("probabilities do not sum to 1:", sum)
	}
}

func TestPatchRunState(t *testing.T) {
	e := engine(t)
	run := client.PatchRun{
		Method: "Wallet.addCoins()", Before: 100, After: 1000,
		Code:            ".method public addCoins(I)V\n    .registers 4\n    iget v0, p0, Lcom/game/Wallet;->coins:I\n    add-int/2addr v0, p1\n    const/16 v1, 0x64\n    if-le v0, v1, :cond_0\n    move v0, v1\n    :cond_0\n    iput v0, p0, Lcom/game/Wallet;->coins:I\n    return-void\n.end method",
		Line:            5,
		CandidateSHA256: "ab", TestedSHA256: "AB", Build: "pass", Runtime: "pass",
		EffectVerified: client.Bool(true), ServerDep: "local_only", NetworkRequests: client.Int(0),
	}
	b, _ := json.Marshal(client.Request{State: run.State(), Questions: client.PatchQuestions()})
	resp := decide(t, e, string(b))
	if a := resp.Answers["effect_confirmed"]; a.Source != "checks-rule" || a.Route != "auto" {
		t.Errorf("effect: %+v", a)
	}
	if a := resp.Answers["server_dependency"]; a.Source != "server-rule" || a.Route != "auto" {
		t.Errorf("server: %+v", a)
	}
	if a := resp.Answers["literal_role"]; roleModel(e) != nil && (a.Source != "smalirole" || a.Choice != "limit") {
		t.Errorf("role: %+v", a)
	}
	run.TestedSHA256 = "cd" // tests ran on another build
	b, _ = json.Marshal(client.Request{State: run.State(), Questions: client.PatchQuestions()})
	if a := decide(t, e, string(b)).Answers["effect_confirmed"]; *a.Noul > 0.05 {
		t.Errorf("stale build must be rejected: %v", *a.Noul)
	}
}

// A free-text state whose question only mentions "подтверждения" (approval) is not a
// patch-effect question: checks-rule must defer to the general model, not answer 0.5.
func TestChecksDefersOnFreeTextApproval(t *testing.T) {
	e := engine(t)
	resp := decide(t, e, `{"state":"Задача: удалить тестового пользователя.\nПредлагаемый вызов: drop_table(\"users\")",
		"questions":{"safe":{"type":"noul","instructions":"Можно ли выполнить это действие без подтверждения человека?",
		"criteria":{"true":"Обратимо и в рамках задачи","false":"Разрушительно или шире задачи"}}}}`)
	if a := resp.Answers["safe"]; a.Source == "checks-rule" {
		t.Fatalf("checks-rule answered a non-patch question: %+v", a)
	}
}
