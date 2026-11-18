// smali-role: typed "what does this literal do?" decisions for Smali constants.
//
//	smali-role -file M.smali -line 4 [-model models/smalirole.json] [-threshold 0.6] [-text] [-app apktool_dir] [-class Lcom/foo/Bar;]
//	smali-role dataset -root decoded_apps/ -out data.jsonl [-cap 300]
//	smali-role train   -data data.jsonl -out models/smalirole.json
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"decisionai/smalirole"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dataset":
			dataset(os.Args[2:])
			return
		case "train":
			train(os.Args[2:])
			return
		case "scan":
			scan(os.Args[2:])
			return
		}
	}
	analyze(os.Args[1:])
}

func analyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	file := fs.String("file", "", "smali method file")
	line := fs.Int("line", 0, "1-based line of the const")
	thr := fs.Float64("threshold", 0.6, "abstain below this confidence")
	modelPath := fs.String("model", "", "trained model JSON (optional)")
	text := fs.Bool("text", false, "print only the explanation")
	appDir := fs.String("app", "", "apktool output dir: follow fields/callees across the app")
	class := fs.String("class", "", "class of the method, e.g. Lcom/foo/Bar; (auto-detected with -app)")
	fs.Parse(args)
	b, err := os.ReadFile(*file)
	if err != nil {
		die(err)
	}
	var m *smalirole.Model
	if *modelPath != "" {
		if m, err = smalirole.LoadModel(*modelPath); err != nil {
			die(err)
		}
	}
	var app *smalirole.App
	if *appDir != "" {
		if app, err = smalirole.LoadApp(*appDir, false); err != nil {
			die(err)
		}
		if *class == "" {
			*class = app.Locate(string(b))
		}
	}
	rep, err := smalirole.AnalyzeCtx(smalirole.Request{Code: string(b), Line: *line, Threshold: thr, Class: *class}, m, app.Ctx())
	if err != nil {
		die(err)
	}
	if *text {
		fmt.Println(rep.Explanation)
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(rep)
}

func dataset(args []string) {
	fs := flag.NewFlagSet("dataset", flag.ExitOnError)
	root := fs.String("root", "", "directory with one apktool output dir per app")
	out := fs.String("out", "smalirole-data.jsonl", "output JSONL")
	cap := fs.Int("cap", 300, "max examples per label per app")
	fs.Parse(args)
	f, err := os.Create(*out)
	if err != nil {
		die(err)
	}
	defer f.Close()
	st, err := smalirole.BuildDataset(*root, bufio.NewWriter(f), *cap)
	if err != nil {
		die(err)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
}

// split assigns whole apps to fit / calibration / test (60/20/20) by a stable hash.
func split(app string) int {
	h := sha1.Sum([]byte(app))
	switch v := int(h[0]) % 10; {
	case v < 6:
		return 0
	case v < 8:
		return 1
	}
	return 2
}

func train(args []string) {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	data := fs.String("data", "", "JSONL from `dataset`")
	out := fs.String("out", "smalirole-model.json", "model output")
	epochs := fs.Int("epochs", 8, "epochs")
	fs.Parse(args)
	f, err := os.Open(*data)
	if err != nil {
		die(err)
	}
	var parts [3][]smalirole.Example
	apps := [3]map[string]bool{{}, {}, {}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e smalirole.Example
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			k := split(e.App)
			parts[k] = append(parts[k], e)
			apps[k][e.App] = true
		}
	}
	m := smalirole.Train(parts[0], smalirole.TrainOptions{Epochs: *epochs, LR: 0.1, L2: 1e-4, MinFreq: 3, Seed: 1})
	pre := m.Evaluate(parts[2], false, nil)
	m.Temperature = m.FitTemperature(parts[1], false)
	m.TempFull = m.FitTemperature(parts[1], true)
	masked := m.Evaluate(parts[2], false, nil)
	fullModel := m.Evaluate(parts[2], true, nil)
	m.Metrics = map[string]any{
		"split_apps":               []int{len(apps[0]), len(apps[1]), len(apps[2])},
		"split_examples":           []int{len(parts[0]), len(parts[1]), len(parts[2])},
		"test_masked_uncalibrated": pre,
		"test_masked_calibrated":   masked,
		"test_full_context":        fullModel,
		"note":                     "labels are weak (typed sinks + public.xml); masked = the labelling use is hidden, so it measures generalisation, full = agreement with the rules",
	}
	if err := m.Save(*out); err != nil {
		die(err)
	}
	b, _ := json.MarshalIndent(m.Metrics, "", " ")
	fmt.Println(string(b))
}
