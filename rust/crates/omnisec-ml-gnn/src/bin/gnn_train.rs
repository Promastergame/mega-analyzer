//! `gnn-train` — trains the OmniSec DEX-license GNN and writes weights the Go
//! runtime loads (`rust/gnn_weights.json`).
//!
//! Usage:
//!   gnn-train [--dataset dex-synth|synth|<path.jsonl|dir>] [--n-per-class N]
//!             [--epochs N] [--lr F] [--seed N] [--out FILE] [--confirmed-only]
//!
//! Examples:
//!   # bootstrap smoke-test on synthetic DEX graphs
//!   gnn-train --dataset dex-synth --n-per-class 400 --epochs 80
//!
//!   # real training on graphs the scanner collected during scans
//!   gnn-train --dataset ~/.analyzer/gnn-dataset --confirmed-only \
//!             --out rust/gnn_weights.json
//!
//! The model architecture is [`ModelConfig::dex_v3`] — a deeper/wider net than
//! the inference default. Weights carry their own config, so a model trained
//! here loads and runs on the exact architecture it was trained with.

use std::env;
use std::process::exit;

use omnisec_ml_gnn::{CLASS_NAMES, ModelConfig, TrainConfig, Trainer, dex_synth, synth};

fn usage() {
    eprintln!(
        "gnn-train [--dataset dex-synth|synth|<path>] [--n-per-class N] [--epochs N]\n          [--lr F] [--seed N] [--out FILE] [--confirmed-only]\n          [--drop-legacy-features] [--allow-graph-split]\n          [--mix-synth N] [--no-class-weighting]"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut dataset = String::from("dex-synth");
    let mut n_per_class: usize = 400;
    let mut epochs: usize = 80;
    let mut lr: f32 = 5e-3;
    let mut seed: u64 = 1337;
    let mut out = String::from("rust/gnn_weights.json");
    let mut confirmed_only = false;
    let mut mix_synth: usize = 0;
    let mut no_class_weighting = false;
    let mut drop_legacy = false;
    let mut allow_graph_split = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dataset" => {
                i += 1;
                dataset = args.get(i).cloned().unwrap_or(dataset);
            }
            "--n-per-class" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    n_per_class = v;
                }
            }
            "--epochs" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    epochs = v;
                }
            }
            "--lr" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    lr = v;
                }
            }
            "--seed" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    seed = v;
                }
            }
            "--mix-synth" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    mix_synth = v;
                }
            }
            "--no-class-weighting" => {
                no_class_weighting = true;
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or(out);
            }
            "--confirmed-only" => {
                confirmed_only = true;
            }
            "--drop-legacy-features" => {
                drop_legacy = true;
            }
            "--allow-graph-split" => {
                allow_graph_split = true;
            }
            "-h" | "--help" => {
                usage();
                return;
            }
            other => {
                eprintln!("gnn-train: unknown argument {other}");
                usage();
                exit(2);
            }
        }
        i += 1;
    }

    eprintln!("gnn-train: dataset={dataset} epochs={epochs} lr={lr} seed={seed}");
    // For real datasets we split by APK (grouped) so one app never appears in
    // both train and val; for the synthetic bootstrap a random split is fine.
    let (mut examples, mut explicit_val): (Vec<_>, usize) = match dataset.as_str() {
        "dex-synth" => (dex_synth::build_dataset(n_per_class, seed), 0usize),
        "synth" => (synth::build_dataset(n_per_class, seed), 0usize),
        path => match dex_synth::load_jsonl_grouped_ex(path, confirmed_only, drop_legacy) {
            Ok((ex, groups)) => {
                // Count distinct source apps BEFORE the split consumes the
                // group vector: with a single app there is no group to hold
                // out, and the old code then fell back to a random
                // graph-level split — methods of the SAME app ended up on
                // both sides, so the reported score measured memorisation.
                let n_groups = {
                    let mut set = std::collections::HashSet::new();
                    for g in &groups {
                        set.insert(g.as_str());
                    }
                    set.len()
                };
                let grouped_split_possible = n_groups >= 2;
                let (reordered, n_val) = dex_synth::group_split_by_apk(ex, groups, 0.2);
                if n_val == 0 && !grouped_split_possible && !allow_graph_split {
                    eprintln!(
                        "gnn-train: ERROR: dataset has only {n_groups} distinct APK group(s), so no \
                         by-APK validation split is possible. Refusing to fall back to a graph-level \
                         split: methods of the same app would appear in train AND validation, and the \
                         reported val_acc/val_macro_f1 would not measure generalisation to a new app."
                    );
                    eprintln!(
                        "gnn-train: scan at least one more APK, or pass --allow-graph-split to accept \
                         a training-only run whose validation score is not a generalisation estimate."
                    );
                    exit(1);
                }
                if n_val == 0 && !grouped_split_possible {
                    eprintln!(
                        "gnn-train: WARNING: falling back to a graph-level split ({n_groups} APK group). \
                         val_acc/val_macro_f1 are NOT generalisation estimates."
                    );
                } else {
                    eprintln!(
                        "gnn-train: by-APK split — {} val graph(s) held out, {} train",
                        n_val,
                        reordered.len().saturating_sub(n_val)
                    );
                }
                (reordered, n_val)
            }
            Err(e) => {
                eprintln!("gnn-train: dataset load failed: {e}");
                exit(1);
            }
        },
    };
    // Fine-tune mode: blend synthetic labelled graphs into the training
    // portion only. `explicit_val` marks the LEADING real examples as
    // validation (shuffle_split=false), so appending here leaves the real
    // validation set untouched — it stays an honest clean-app FP probe.
    if mix_synth > 0 && explicit_val > 0 {
        let mut synth_examples = dex_synth::build_dataset(mix_synth, seed);
        // Hold a fifth of the synthetic graphs out for validation: an
        // all-benign real val set would saturate val_acc at epoch 1 and
        // early-stop before the class heads learn anything.
        let n_synth_val = synth_examples.len() / 5;
        let synth_val: Vec<_> = synth_examples.drain(..n_synth_val).collect();
        let n_synth_train = synth_examples.len();
        let real_val: Vec<_> = examples.drain(..explicit_val).collect();
        let mut train_part = examples;
        let mut combined_val = real_val;
        combined_val.extend(synth_val);
        train_part.extend(synth_examples);
        explicit_val = combined_val.len();
        examples = combined_val;
        examples.extend(train_part);
        eprintln!(
            "gnn-train: mixing {} synthetic graph(s) ({n_synth_val} into val)",
            n_synth_train + n_synth_val
        );
    }
    eprintln!("gnn-train: {} training example(s)", examples.len());

    let cfg = ModelConfig::dex_v3();
    let mut trainer = Trainer::new(cfg, seed);
    let tc = TrainConfig {
        epochs,
        learning_rate: lr,
        seed,
        shuffle_split: explicit_val == 0,
        explicit_val,
        class_weighting: !no_class_weighting,
        ..TrainConfig::default()
    };

    let report = match trainer.fit(&examples, &tc) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gnn-train: fit failed: {e}");
            exit(1);
        }
    };
    eprintln!(
        "gnn-train: best_epoch={} val_acc={:.4} val_macro_f1={:.4} (train {}, val {})",
        report.best_epoch,
        report.best_val_acc,
        report.best_val_macro_f1,
        report.train_examples,
        report.val_examples,
    );

    let mut store = trainer.to_weight_store(
        report.train_examples,
        report.best_val_acc,
        report.best_epoch,
    );
    // Persist full provenance: without these the file can't answer
    // "which run produced this model?" (previously left as Default).
    store.metadata.val_macro_f1 = report.best_val_macro_f1;
    store.metadata.seed = Some(seed);
    store.metadata.train_config = Some(tc);
    if let Err(e) = store.save_json(&out) {
        eprintln!("gnn-train: failed to write {out}: {e}");
        exit(1);
    }
    eprintln!("gnn-train: wrote {out}");
    eprintln!("gnn-train: classes:");
    for (idx, name) in CLASS_NAMES.iter().enumerate() {
        eprintln!("  {idx}: {name}");
    }
}
