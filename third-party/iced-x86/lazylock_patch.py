"""Replace lazy_static! blocks with std::sync::LazyLock statics.

Transform:
    lazy_static! {
        VIS static ref NAME: TYPE = INIT;
    }
->
    VIS static NAME: std::sync::LazyLock<TYPE> = std::sync::LazyLock::new(|| INIT);

INIT is either a single expression (`read();`) or a brace-balanced block.
Lexer-aware brace matching skips strings, char literals and comments.
Also drops `use lazy_static::lazy_static;` lines and the
`#![allow(clippy::let_unit_value)]` inner attribute (unstable inside
closure bodies; plain builds never fire that lint).
Fails loudly on any unexpected shape.
"""
import re
import sys
from pathlib import Path

FILES = [
    "src/decoder/handlers/tables.rs",
    "src/encoder/handlers_table.rs",
    "src/encoder/op_code_tbl.rs",
    "src/formatter/fmt_consts.rs",
    "src/formatter/pseudo_ops.rs",
    "src/formatter/regs_tbl_ls.rs",
    "src/formatter/fast/fmt_tbl.rs",
    "src/formatter/fast/mem_size_tbl.rs",
    "src/formatter/fast/pseudo_ops_fast.rs",
    "src/formatter/fast/regs.rs",
    "src/formatter/gas/fmt_tbl.rs",
    "src/formatter/gas/mem_size_tbl.rs",
    "src/formatter/gas/regs.rs",
    "src/formatter/intel/fmt_tbl.rs",
    "src/formatter/intel/mem_size_tbl.rs",
    "src/formatter/masm/fmt_tbl.rs",
    "src/formatter/masm/mem_size_tbl.rs",
    "src/formatter/nasm/fmt_tbl.rs",
    "src/formatter/nasm/mem_size_tbl.rs",
    "src/formatter/nasm/regs.rs",
]

USE_LINE = re.compile(r"^[ \t]*use lazy_static::lazy_static;[ \t]*\r?\n", re.M)


def find_matching(text: str, open_idx: int, open_c: str, close_c: str) -> int:
    """Index of the brace matching text[open_idx], skipping strings/comments."""
    assert text[open_idx] == open_c
    i = open_idx + 1
    depth = 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == open_c:
            depth += 1
            i += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
            i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1  # closing quote
        elif c == "'":
            # char literal or lifetime: skip 'x' / 'label
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
            else:
                while j < n and (text[j].isalnum() or text[j] == "_"):
                    j += 1
            if j < n and text[j] == "'":
                i = j + 1
            else:
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
        else:
            i += 1
    raise ValueError("unbalanced braces")


def transform_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    orig = text
    # 1. Drop the import.
    text, n_use = USE_LINE.subn("", text)
    # 2. Drop the unstable inner attribute (see docstring).
    text, n_attr = re.subn(
        r"^[ \t]*#\!\[allow\(clippy::let_unit_value\)\][ \t]*\r?\n", "", text, flags=re.M
    )
    count = 0
    while True:
        m = re.search(r"lazy_static!\s*\{", text)
        if not m:
            break
        brace_open = text.index("{", m.start())
        brace_close = find_matching(text, brace_open, "{", "}")
        inner = text[brace_open + 1 : brace_close]
        # Expect exactly one `static ref` item (attrs allowed).
        sm = re.fullmatch(
            r"(?s)\s*((?:#[^\n]*\n\s*)*)(pub\([^)]*\)|pub|)\s*static ref (?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<ty>.*?)\s*=\s*(?P<init>.*?)\s*;?\s*",
            inner,
        )
        if not sm:
            raise ValueError(f"{path}: unexpected lazy_static body:\n{inner[:400]}")
        attrs, vis, name, ty, init = (
            sm.group(1),
            sm.group(2),
            sm.group("name"),
            sm.group("ty"),
            sm.group("init"),
        )
        if attrs.strip():
            raise ValueError(f"{path}:{name}: attributes on static need manual review")
        vis_prefix = (vis + " ") if vis else ""
        init = init.strip()
        if not init.startswith("{"):
            init_expr = init.rstrip(";").strip()
            new_init = init_expr
        else:
            new_init = init
        replacement = (
            f"{vis_prefix}static {name}: std::sync::LazyLock<{ty.strip()}> = "
            f"std::sync::LazyLock::new(|| {new_init});"
        )
        text = text[: m.start()] + replacement + text[brace_close + 1 :]
        # Drop one trailing `;`? lazy_static blocks in these files end with
        # `}` and no semicolon (verified); guard anyway.
        count += 1
    if text == orig and count == 0:
        raise ValueError(f"{path}: no lazy_static block found")
    path.write_text(text, encoding="utf-8")
    print(f"{path.name}: {count} block(s), {n_use} use-line(s), {n_attr} attr-line(s) removed")
    return count


def main() -> None:
    root = Path(sys.argv[1])
    total = 0
    for rel in FILES:
        total += transform_file(root / rel)
    print(f"TOTAL blocks transformed: {total}")


if __name__ == "__main__":
    main()
