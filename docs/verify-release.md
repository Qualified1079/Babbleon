# Verifying a Babbleon release

Every release tag triggers `.github/workflows/release.yml`, which:

1. Builds the workspace targeting `x86_64-unknown-linux-musl`
   (statically-linked binaries, no glibc surface).
2. Generates a CycloneDX SBOM for the workspace.
3. Signs the release tarball **and** the SBOM with sigstore via
   keyless cosign — the signing identity is the workflow's OIDC
   identity, not a long-lived secret in the repo.
4. Produces SLSA L3 provenance via the official
   `slsa-framework/slsa-github-generator` reusable workflow.
5. Attaches everything to a draft GitHub Release.

Each release page therefore has at least five files:

| File | What it is |
|---|---|
| `babbleon-<TAG>-x86_64-linux-musl.tar.gz`         | The release binaries |
| `babbleon-<TAG>-x86_64-linux-musl.tar.gz.sha256`  | SHA-256 digest |
| `babbleon-<TAG>-x86_64-linux-musl.tar.gz.cosign.bundle` | Sigstore signature + tlog proof |
| `babbleon-<TAG>-sbom.cdx.json`                    | CycloneDX SBOM |
| `babbleon-<TAG>-sbom.cdx.json.cosign.bundle`      | Signature on the SBOM |
| `*.intoto.jsonl`                                  | SLSA provenance attestation |

## Tooling

Install `cosign` (sigstore) and `slsa-verifier`:

```sh
# cosign — GitHub release of sigstore/cosign
curl -sSfL -o cosign \
  https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign && sudo mv cosign /usr/local/bin/cosign

# slsa-verifier
curl -sSfL -o slsa-verifier \
  https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64
chmod +x slsa-verifier && sudo mv slsa-verifier /usr/local/bin/slsa-verifier
```

## Verify the signature

```sh
TAG=v0.1.0
ART=babbleon-${TAG}-x86_64-linux-musl.tar.gz

cosign verify-blob \
  --bundle "${ART}.cosign.bundle" \
  --certificate-identity-regexp '^https://github.com/qualified1079/babbleon/.github/workflows/release.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${ART}"
```

A successful run prints `Verified OK`.  Failure modes:

- **Bundle / artifact pair mismatched** — re-download both from the
  same release page; `cosign.bundle` is artifact-specific.
- **Identity didn't match the regexp** — confirm the release came
  from this repo's `release.yml` workflow.  Forks build their own
  identities; the regexp pins the path.
- **OIDC issuer didn't match** — only GitHub-hosted runners' OIDC
  identities are accepted.  Self-hosted runners with their own
  issuer would need a different identity rule.

## Verify the SLSA provenance

```sh
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/qualified1079/babbleon \
  --source-tag "${TAG}" \
  "${ART}"
```

This checks that the artifact was produced by a tagged build of this
exact repo's release workflow on a hosted GitHub runner — the SLSA
L3 build-isolation claim.

## Verify the SBOM

```sh
SBOM=babbleon-${TAG}-sbom.cdx.json

cosign verify-blob \
  --bundle "${SBOM}.cosign.bundle" \
  --certificate-identity-regexp '^https://github.com/qualified1079/babbleon/.github/workflows/release.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${SBOM}"
```

Once verified, the SBOM is a faithful manifest of every dependency
crate and version that went into the build.  Cross-check against
your own internal allow-list or feed it to an SCA scanner.

## Why this matters

`cosign` + SLSA provenance is the supply-chain answer to "the artifact
we downloaded was actually produced by the source tree we expect, on
infrastructure we can identify, and nothing in the middle swapped it
out".  Without these checks the only thing standing between a user
and a malicious mirror is HTTPS + GitHub's auth — sufficient for
hobby use, insufficient for any procurement pitch.

For the threat model that motivates each of these layers, see
`docs/threat-model.md`.
