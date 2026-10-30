/* NIF table for omnisec_debugger_nif — built with the real erl_nif.h.
 * The functions below are implemented in Rust (see lib.rs) via
 * `nifshim::nif_entry!` and exported with matching `#[no_mangle]` names. */
#include "erl_nif.h"

extern ERL_NIF_TERM raw_debug_session_start(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_session_stop(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_step(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_continue(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_breakpoint(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_remove_bp(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_registers(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_disassemble(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_read_memory(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_set_flavor(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_list_bp(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_add_watch(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_remove_watch(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_list_watch(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_write_memory(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_trace_enable(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_reverse_step(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_reverse_continue(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_scan_memory(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_set_register(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_set_flag(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_trace_log(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_trace_stats(ErlNifEnv *, int, const ERL_NIF_TERM[]);
extern ERL_NIF_TERM raw_debug_cfg(ErlNifEnv *, int, const ERL_NIF_TERM[]);

static ErlNifFunc nif_funcs[] = {
    {"debug_session_start", 1, raw_debug_session_start, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_session_stop", 1, raw_debug_session_stop, 0},
    {"debug_step", 1, raw_debug_step, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_continue", 1, raw_debug_continue, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_breakpoint", 2, raw_debug_breakpoint, 0},
    {"debug_remove_bp", 2, raw_debug_remove_bp, 0},
    {"debug_registers", 1, raw_debug_registers, 0},
    {"debug_disassemble", 3, raw_debug_disassemble, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_read_memory", 3, raw_debug_read_memory, 0},
    {"debug_set_flavor", 2, raw_debug_set_flavor, 0},
    {"debug_list_bp", 1, raw_debug_list_bp, 0},
    {"debug_add_watch", 4, raw_debug_add_watch, 0},
    {"debug_remove_watch", 2, raw_debug_remove_watch, 0},
    {"debug_list_watch", 1, raw_debug_list_watch, 0},
    {"debug_write_memory", 3, raw_debug_write_memory, 0},
    {"debug_trace_enable", 2, raw_debug_trace_enable, 0},
    {"debug_reverse_step", 1, raw_debug_reverse_step, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_reverse_continue", 1, raw_debug_reverse_continue, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_scan_memory", 2, raw_debug_scan_memory, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"debug_set_register", 3, raw_debug_set_register, 0},
    {"debug_set_flag", 3, raw_debug_set_flag, 0},
    {"debug_trace_log", 3, raw_debug_trace_log, 0},
    {"debug_trace_stats", 1, raw_debug_trace_stats, 0},
    {"debug_cfg", 3, raw_debug_cfg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

#define nif_init c_nif_init
ERL_NIF_INIT(Elixir.OmnisecServer.NativeDebugger, nif_funcs, NULL, NULL, NULL, NULL)
