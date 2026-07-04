# Vendored tokenizer files

Two open-weights tokenizer definitions, vendored so the `--include-
sentencepiece` benchmark run is reproducible without a network
fetch. Both are the HuggingFace "fast tokenizer" `tokenizer.json`
format, loaded via the `tokenizers` crate (pure Rust; no native
SentencePiece/protobuf dependency needed).

Fetched 2026-07-04.

| Directory          | Source                                                                          | License    | sha256                                                            |
|---------------------|----------------------------------------------------------------------------------|------------|--------------------------------------------------------------------|
| `mistral-7b-v0.1/`  | `https://huggingface.co/mistralai/Mistral-7B-v0.1/resolve/main/tokenizer.json`   | Apache-2.0 | `11c08db21487c885d8c792180f0be237f6a261b89a46f128a6a80a3aa4bd1720` |
| `phi-2/`            | `https://huggingface.co/microsoft/phi-2/resolve/main/tokenizer.json`            | MIT        | `337da36be7a71a6e88aa9148967a7bc8736f4b47c7de8e19ba92b89e80734cfc` |

## Why these two, not Llama-3

Llama-3's own tokenizer is the one `docs/v2/obfuscation-landscape.md`
and `TODO.md` actually name as the hypothesis target, but its
`tokenizer.json` on HuggingFace is gated behind a license
click-through — not fetchable without an authenticated, license-
accepting HF account. Mistral-7B-v0.1 (32k vocab, SentencePiece BPE)
and Phi-2 (50 295 vocab, GPT-NeoX-style BPE) are both openly licensed
and serve the same purpose the hypothesis actually cares about:
smaller, non-frontier, open-weights vocabularies as a contrast to
OpenAI's tiktoken families (`cl100k_base` 100k / `o200k_base` 200k).
If a future session gets authenticated HF access and wants the exact
Llama-3 tokenizer too, it slots into the same `--include-sentencepiece`
mechanism — add a third `Tokenizer::from_file` load and a third set of
parallel vectors, mirroring the Mistral/Phi-2 wiring in `src/main.rs`.

## Re-fetching

```
curl -sSL -o mistral-7b-v0.1/tokenizer.json \
  https://huggingface.co/mistralai/Mistral-7B-v0.1/resolve/main/tokenizer.json
curl -sSL -o phi-2/tokenizer.json \
  https://huggingface.co/microsoft/phi-2/resolve/main/tokenizer.json
sha256sum mistral-7b-v0.1/tokenizer.json phi-2/tokenizer.json
```

Confirm the sha256 still matches the table above (or update the table
if the upstream file legitimately changed) before trusting a re-fetch.
