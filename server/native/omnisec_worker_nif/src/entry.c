/* NIF table for omnisec_worker_nif — built with the real erl_nif.h.
 * The functions below are implemented in Rust (see lib.rs) via
 * `nifshim::nif_entry!` and exported with matching `#[no_mangle]` names. */
#include "erl_nif.h"

extern ERL_NIF_TERM raw_analyze_apk(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_analyze_binary(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_scan_patterns(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_rank_hotspots(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_hash_features(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_health_check(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_scan_yara(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_predict_variable_name(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_predict_function_name(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_train_variable_name(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_train_function_name(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_ebpf_start_trace(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_ebpf_poll_events(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_ebpf_stop_trace(ErlNifEnv *, int, const ERL_NIF_TERM[]);

static ErlNifFunc nif_funcs[] = {
    {"analyze_apk", 1, raw_analyze_apk, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"analyze_binary", 1, raw_analyze_binary, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"scan_patterns", 2, raw_scan_patterns, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"rank_hotspots", 1, raw_rank_hotspots, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"hash_features", 2, raw_hash_features, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"health_check", 0, raw_health_check, 0},
    {"scan_yara", 2, raw_scan_yara, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"predict_variable_name", 3, raw_predict_variable_name, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"predict_function_name", 3, raw_predict_function_name, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"train_variable_name", 3, raw_train_variable_name, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"train_function_name", 3, raw_train_function_name, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ebpf_start_trace", 1, raw_ebpf_start_trace, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ebpf_poll_events", 1, raw_ebpf_poll_events, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ebpf_stop_trace", 1, raw_ebpf_stop_trace, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

#define nif_init c_nif_init
ERL_NIF_INIT(Elixir.OmnisecServer.Native, nif_funcs, NULL, NULL, NULL, NULL)
