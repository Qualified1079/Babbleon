"""Install-time diversification of an LLM agent's semantic surface.

Core idea (see /claude.md for the full thesis and its scope boundary):
most agent deployments expose the same tool names, parameter names, and
prompt/marker vocabulary as every other deployment of the same framework.
That monoculture is what lets a single prompt-injection worm payload
transfer cleanly across the whole population. `Dialect.generate` takes a
per-install seed and an `AgentSurface` (the canonical tool/prompt/marker
vocabulary) and deterministically derives a diversified surface: same
seed always yields the same dialect, different seeds yield different,
mutually unintelligible dialects. `babbleon.runtime.DialectRuntime`
translates between a dialect and the canonical implementation so
application behavior is unaffected by which dialect is in front of it.

This is intentionally install-granularity (one dialect per deployment,
stable across requests), not request-granularity like Polymorphic Prompt
Assembling's separator randomization (arXiv:2506.05739) — see claude.md
for why those are complementary, not overlapping, defenses.
"""
from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from typing import Dict, Tuple

# Small synonym pools used for both tool/parameter name aliasing and
# system-prompt word substitution, so a dialect's vocabulary is
# self-consistent (the same install that calls it "dispatch_mail" also
# talks about "dispatching mail" in its own system prompt).
_VERB_SYNONYMS = {
    "send": ("dispatch", "transmit", "relay", "post"),
    "get": ("fetch", "retrieve", "pull", "obtain"),
    "search": ("query", "lookup", "scan", "probe"),
    "list": ("enumerate", "collect", "gather"),
    "create": ("spawn", "issue", "compose"),
    "delete": ("remove", "purge", "discard"),
    "read": ("inspect", "peek", "load"),
    "write": ("store", "record", "persist"),
    "forward": ("relay", "route", "redirect"),
    "reply": ("respond", "answer", "acknowledge"),
    "call": ("invoke", "trigger", "ping"),
    "update": ("revise", "amend", "patch"),
}

_NOUN_SYNONYMS = {
    "email": ("mail", "message", "note", "memo"),
    "message": ("mail", "note", "memo", "text"),
    "web": ("net", "online", "remote"),
    "file": ("doc", "record", "artifact"),
    "user": ("account", "person", "member"),
    "contact": ("entry", "person", "record"),
    "document": ("file", "record", "doc"),
    "address": ("recipient", "destination", "target"),
}

_WORD_RE = re.compile(r"[A-Za-z]+")


def _alias_word(word: str, rng: random.Random) -> str:
    lw = word.lower()
    pool = _VERB_SYNONYMS.get(lw) or _NOUN_SYNONYMS.get(lw)
    return rng.choice(pool) if pool else word


def _alias_name(name: str, rng: random.Random) -> str:
    """Alias a snake_case tool/parameter name and append a per-install salt.

    The salt guarantees every diversified name differs from the
    canonical one even when no word in it is in the synonym pool ---
    but note (see claude.md's honest-limitation section) a salt-only
    rename is the shallow end of diversification: it defeats literal
    string matching, nothing more.
    """
    parts = name.split("_")
    aliased = [_alias_word(p, rng) for p in parts if p]
    salt = format(rng.getrandbits(16), "04x")
    return "_".join(aliased + [salt])


def _alias_text(text: str, rng: random.Random) -> str:
    def repl(match: "re.Match[str]") -> str:
        word = match.group(0)
        lw = word.lower()
        pool = _VERB_SYNONYMS.get(lw) or _NOUN_SYNONYMS.get(lw)
        if not pool:
            return word
        choice = rng.choice(pool)
        if word.isupper():
            return choice.upper()
        if word[0].isupper():
            return choice.capitalize()
        return choice

    return _WORD_RE.sub(repl, text)


def _alias_marker(seed: str, key: str) -> str:
    """Derive a per-install control token for a logical marker key.

    Hash-derived (not rng-sequence-derived) so it doesn't depend on how
    many other rng draws happened first --- keeps marker tokens stable
    even if tool/param aliasing logic changes.
    """
    digest = hashlib.sha256(f"{seed}:marker:{key}".encode()).hexdigest()[:6].upper()
    return f"X{digest}_{key.upper()[:4]}"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentSurface:
    """The semantic surface an agent presents: prompt, tools, control markers.

    `markers` maps a logical key (e.g. "forward") to the literal token
    used in the system prompt / expected in incoming payloads (e.g.
    "FORWARD_TO"). Diversifying this is what breaks a worm payload that
    depends on the target recognizing a specific literal control token.
    """

    system_prompt: str
    tools: Tuple[ToolSpec, ...]
    markers: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Dialect:
    """A deterministic, per-seed diversified view of a canonical AgentSurface."""

    seed: str
    surface: AgentSurface
    tool_name_map: Dict[str, str]  # diversified tool name -> canonical tool name
    param_name_map: Dict[Tuple[str, str], str]  # (canonical tool, diversified param) -> canonical param
    marker_map: Dict[str, str]  # diversified token -> logical marker key

    @staticmethod
    def generate(seed: str, surface: AgentSurface) -> "Dialect":
        rng = random.Random(seed)

        tool_name_map: Dict[str, str] = {}
        param_name_map: Dict[Tuple[str, str], str] = {}
        new_tools = []
        for tool in surface.tools:
            diversified_name = _alias_name(tool.name, rng)
            tool_name_map[diversified_name] = tool.name

            new_params = []
            for param in tool.params:
                diversified_param = _alias_name(param, rng)
                param_name_map[(tool.name, diversified_param)] = param
                new_params.append(diversified_param)

            new_description = _alias_text(tool.description, rng)
            new_tools.append(ToolSpec(diversified_name, new_description, tuple(new_params)))

        marker_map: Dict[str, str] = {}
        token_replacements: Dict[str, str] = {}
        new_markers: Dict[str, str] = {}
        for key, canonical_token in surface.markers.items():
            diversified_token = _alias_marker(seed, key)
            marker_map[diversified_token] = key
            token_replacements[canonical_token] = diversified_token
            new_markers[key] = diversified_token

        # Replace marker tokens first, on the raw prompt: word-level
        # aliasing below would otherwise mangle a literal token like
        # "FORWARD_TO" into "ROUTE_TO" before we get a chance to match it.
        prompt_with_markers_swapped = surface.system_prompt
        for canonical_token, diversified_token in token_replacements.items():
            prompt_with_markers_swapped = prompt_with_markers_swapped.replace(
                canonical_token, diversified_token
            )
        new_prompt = _alias_text(prompt_with_markers_swapped, rng)

        new_surface = AgentSurface(
            system_prompt=new_prompt,
            tools=tuple(new_tools),
            markers=new_markers,
        )

        return Dialect(
            seed=seed,
            surface=new_surface,
            tool_name_map=tool_name_map,
            param_name_map=param_name_map,
            marker_map=marker_map,
        )
