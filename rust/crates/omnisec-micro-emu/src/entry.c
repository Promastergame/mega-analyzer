/* NIF table for omnisec_micro_emu_nif — built with the real erl_nif.h. */
#include "erl_nif.h"

extern ERL_NIF_TERM raw_emulate_shellcode(ErlNifEnv *, int, const ERL_NIF_TERM[]);

static ErlNifFunc nif_funcs[] = {
    {"emulate_shellcode", 1, raw_emulate_shellcode, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

#define nif_init c_nif_init
ERL_NIF_INIT(Elixir.OmniSec.Native.MicroEmu, nif_funcs, NULL, NULL, NULL, NULL)
