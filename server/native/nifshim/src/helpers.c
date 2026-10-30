/*
 * nifshim/helpers.c
 *
 * Tiny ABI boundary between Rust and the real erl_nif.h that ships with
 * the Erlang/OTP installation used to build this NIF. Every function
 * here only crosses simple, size-stable types (pointers, size_t,
 * fixed-width integers, ERL_NIF_TERM) to Rust, so Rust never needs to
 * know the exact layout of ErlNifBinary / ErlNifEntry / ErlNifFunc,
 * which differ across OTP releases. Correctness of those layouts is
 * guaranteed here because this file is compiled with the *actual*
 * erl_nif.h for the target OTP (see build.rs), not a hand-copied one.
 */

#include "erl_nif.h"
#include <string.h>

/* ---------------------------------------------------------------- *
 * Binaries
 * ---------------------------------------------------------------- */

int shim_get_binary(ErlNifEnv *env, ERL_NIF_TERM term,
                     const unsigned char **out_data, size_t *out_len) {
    ErlNifBinary bin;
    if (!enif_inspect_binary(env, term, &bin)) {
        return 0;
    }
    *out_data = bin.data;
    *out_len = bin.size;
    return 1;
}

ERL_NIF_TERM shim_make_binary(ErlNifEnv *env, const unsigned char *data, size_t len) {
    ERL_NIF_TERM term;
    unsigned char *buf = enif_make_new_binary(env, len, &term);
    if (len > 0 && buf != NULL) {
        memcpy(buf, data, len);
    }
    return term;
}

/* ---------------------------------------------------------------- *
 * Integers / floats
 * ---------------------------------------------------------------- */

int shim_get_u64(ErlNifEnv *env, ERL_NIF_TERM term, unsigned long long *out) {
    ErlNifUInt64 v;
    if (!enif_get_uint64(env, term, &v)) return 0;
    *out = (unsigned long long)v;
    return 1;
}

int shim_get_i64(ErlNifEnv *env, ERL_NIF_TERM term, long long *out) {
    ErlNifSInt64 v;
    if (!enif_get_int64(env, term, &v)) return 0;
    *out = (long long)v;
    return 1;
}

int shim_get_u32(ErlNifEnv *env, ERL_NIF_TERM term, unsigned int *out) {
    return enif_get_uint(env, term, out);
}

int shim_get_double(ErlNifEnv *env, ERL_NIF_TERM term, double *out) {
    return enif_get_double(env, term, out);
}

ERL_NIF_TERM shim_make_u64(ErlNifEnv *env, unsigned long long v) {
    return enif_make_uint64(env, (ErlNifUInt64)v);
}

ERL_NIF_TERM shim_make_i64(ErlNifEnv *env, long long v) {
    return enif_make_int64(env, (ErlNifSInt64)v);
}

ERL_NIF_TERM shim_make_u32(ErlNifEnv *env, unsigned int v) {
    return enif_make_uint(env, v);
}

ERL_NIF_TERM shim_make_double(ErlNifEnv *env, double v) {
    return enif_make_double(env, v);
}

/* ---------------------------------------------------------------- *
 * Atoms / booleans / nil
 * ---------------------------------------------------------------- */

ERL_NIF_TERM shim_make_atom(ErlNifEnv *env, const char *name) {
    return enif_make_atom(env, name);
}

int shim_is_nil(ErlNifEnv *env, ERL_NIF_TERM term) {
    ERL_NIF_TERM nil = enif_make_atom(env, "nil");
    return enif_is_identical(term, nil);
}

/* Returns 1/0 via *out on success, function return value indicates
 * whether `term` was a recognizable boolean atom at all. */
int shim_get_bool(ErlNifEnv *env, ERL_NIF_TERM term, int *out) {
    char buf[8];
    if (!enif_get_atom(env, term, buf, sizeof(buf), ERL_NIF_LATIN1)) {
        return 0;
    }
    if (strcmp(buf, "true") == 0) {
        *out = 1;
        return 1;
    }
    if (strcmp(buf, "false") == 0) {
        *out = 0;
        return 1;
    }
    return 0;
}

ERL_NIF_TERM shim_make_bool(ErlNifEnv *env, int v) {
    return enif_make_atom(env, v ? "true" : "false");
}

/* ---------------------------------------------------------------- *
 * Errors
 * ---------------------------------------------------------------- */

ERL_NIF_TERM shim_make_badarg(ErlNifEnv *env) {
    return enif_make_badarg(env);
}

/* ---------------------------------------------------------------- *
 * Tuples
 * ---------------------------------------------------------------- */

ERL_NIF_TERM shim_make_tuple2(ErlNifEnv *env, ERL_NIF_TERM a, ERL_NIF_TERM b) {
    return enif_make_tuple2(env, a, b);
}
