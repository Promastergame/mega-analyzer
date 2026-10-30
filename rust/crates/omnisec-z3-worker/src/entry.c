/* NIF table for omnisec_symexec_nif — built with the real erl_nif.h. */
#include "erl_nif.h"

extern ERL_NIF_TERM raw_solve_opaque_predicate(ErlNifEnv *, int, const ERL_NIF_TERM[]);

static ErlNifFunc nif_funcs[] = {
    {"solve_opaque_predicate", 1, raw_solve_opaque_predicate, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

#define nif_init c_nif_init
ERL_NIF_INIT(Elixir.OmniSec.Native.SymExec, nif_funcs, NULL, NULL, NULL, NULL)
