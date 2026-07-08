"""Deterministic, seed-driven syntactic diversification for Python source.

An LLM-driven worm that reasons its way through a network (see handoff.md,
2026-07-08 entry) fingerprints each target by *reading* it: variable names,
control-flow shape, code structure. If every install of the same codebase
looks textually distinct while behaving identically, an exploit chain the
worm derived by reading host A's source doesn't transfer verbatim to host
B — it has to re-derive it, burning inference budget and raising its
chance of a failed, loggable attempt.

This module renames function-local identifiers to seed-derived pseudonyms.
It never touches:
  - parameters (renaming could break keyword-argument call sites)
  - names declared `global`/`nonlocal` in their own function
  - names referenced anywhere inside a nested function/lambda/class
    (closures are excluded rather than risk an incorrect rename)
  - module-level names, imports, function/class names (the public API
    surface must stay stable)
  - dunder names and `self`/`cls`

This is a conservative, no-LLM complement to the (removed) install-time
semantic diversification research track: it needs no model and no GPU,
so it can run on every install/build, with the LLM-based track reserved
for deeper, less-conservative rewrites where the cost is justified.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import keyword
import sys
from pathlib import Path

_SCOPE_BOUNDARY = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_PRESERVED_NAMES = {"self", "cls"}


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _own_scope_nodes(fn: ast.AST):
    """Yield every descendant of fn's body, without descending past a
    nested function/lambda/class boundary (the boundary node itself is
    still yielded, so callers can see it exists, just not what's inside)."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPE_BOUNDARY):
            stack.extend(ast.iter_child_nodes(node))


def _names_in_subtree(node: ast.AST) -> set[str]:
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    names |= {n.name for n in ast.walk(node) if isinstance(n, ast.ExceptHandler) and n.name}
    for n in ast.walk(node):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(n.name)
            names |= _param_names(n)
        elif isinstance(n, ast.ClassDef):
            names.add(n.name)
    return names


def _param_names(fn) -> set[str]:
    args = fn.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _own_global_nonlocal(fn) -> set[str]:
    names: set[str] = set()
    for node in _own_scope_nodes(fn):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def _nested_scope_names(fn) -> set[str]:
    """Names referenced anywhere inside a scope nested within fn, at any depth."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if node is fn:
            continue
        if isinstance(node, _SCOPE_BOUNDARY):
            names |= _names_in_subtree(node)
    return names


def _candidate_names(fn) -> set[str]:
    candidates: set[str] = set()
    for node in _own_scope_nodes(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            candidates.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            candidates.add(node.name)
    return candidates


def _renamable_set(fn) -> set[str]:
    excluded = (
        _param_names(fn)
        | _own_global_nonlocal(fn)
        | _nested_scope_names(fn)
        | _PRESERVED_NAMES
    )
    return {
        name
        for name in _candidate_names(fn)
        if name not in excluded and not _is_dunder(name)
    }


def _pseudonym(seed: str, qualifier: str, old_name: str, taken: set[str]) -> str:
    digest = hashlib.sha256(f"{seed}:{qualifier}:{old_name}".encode()).hexdigest()
    candidate = f"_v{digest[:8]}"
    suffix = 0
    while candidate in taken or keyword.iskeyword(candidate):
        suffix += 1
        candidate = f"_v{digest[:8]}_{suffix}"
    return candidate


def _rename_in_scope(fn, mapping: dict[str, str]) -> None:
    for node in _own_scope_nodes(fn):
        if isinstance(node, ast.Name) and node.id in mapping:
            node.id = mapping[node.id]
        elif isinstance(node, ast.ExceptHandler) and node.name in mapping:
            node.name = mapping[node.name]


def diversify_tree(tree: ast.Module, seed: str) -> ast.Module:
    """Rename safe function-local identifiers throughout tree, in place."""
    module_names = _names_in_subtree(tree)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        renamable = _renamable_set(fn)
        if not renamable:
            continue
        qualifier = f"{fn.name}:{fn.lineno}:{fn.col_offset}"
        taken = module_names | set(renamable)
        mapping: dict[str, str] = {}
        for old_name in sorted(renamable):
            new_name = _pseudonym(seed, qualifier, old_name, taken)
            taken.add(new_name)
            mapping[old_name] = new_name
        _rename_in_scope(fn, mapping)
    return tree


def diversify_source(source: str, seed: str) -> str:
    tree = ast.parse(source)
    diversify_tree(tree, seed)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def diversify_file(path: Path, seed: str) -> str:
    return diversify_source(path.read_text(), seed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rename safe local identifiers to seed-derived pseudonyms."
    )
    parser.add_argument("path", type=Path, help="Python source file to diversify")
    parser.add_argument(
        "--seed", required=True, help="per-install seed; same seed -> same output"
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None, help="write result here (default: stdout)"
    )
    args = parser.parse_args(argv)

    result = diversify_file(args.path, args.seed)
    if args.output:
        args.output.write_text(result)
    else:
        sys.stdout.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
