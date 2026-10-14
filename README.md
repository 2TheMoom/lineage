# Lineage

On-chain chains of custody for software artifacts, built on GenLayer validator consensus. No LLM, no money.

## The problem

A release is usually a chain: source code, then a build, then a package or image made from that build. Each link can be checked against a checksum the publisher lists, but nobody records that anywhere a contract can read, and a checksum list proves nothing about where a file came from.

Lineage records, for one artifact at a time, three things: the exact sha256 validators computed from the bytes, whether the publisher's own checksum list agrees, and which earlier artifact it was built from. Other contracts gate on `is_trusted_from()`, which also pins who vouched for it.

## How it works

1. **`attest(artifact_url, manifest_url, filename, parent_id)`** registers one artifact, the publisher's checksum list that should name it, the name to look for, and optionally the attestation of the artifact it was derived from. The id is the sha256 of all four fields joined with `|` (which none may contain), so the same attestation can't be registered twice and nobody can squat someone else's id with different rules. `attestation_id(...)` computes it.
2. **`check(id)`** is permissionless. Every validator downloads the artifact and the list itself, hashes the artifact with sha256, and reads the list. Validators must agree on the verdict, the computed digest, the listed digest and the size. The verdict is deterministic:

| Status | Meaning |
|---|---|
| `verified` | the digest validators computed equals the digest the publisher lists for this filename (and, for a child, the list also names the parent's digest) |
| `mismatch` | the list names the file with a different digest, or names it twice with different digests |
| `unlisted` | the list does not name this filename |
| `unbound` | the file matches, but the list does not also name the parent's digest |
| `drifted` | was verified, and now the bytes or the list say something else |
| `pending` | registered, never checked |

3. **A chain is a path of attestations.** A child names its parent. `trace(id)` returns the path up to the root and `is_trusted(id, max_check_age_seconds)` is true only if the attestation and every ancestor is `verified` and, when an age is given, was checked that recently. If a root drifts, everything built from it stops being trusted, without anyone touching the children.

   **`is_trusted` alone does not say who vouched.** Anyone can publish a self-consistent chain on their own site, so a consumer should call **`is_trusted_from(id, max_check_age_seconds, manifest_prefix)`**, which additionally requires every link's checksum list to live under a prefix the consumer picks (for example `https://github.com/jqlang/jq/releases/`). The prefix must end in `/`, so `https://github.com/jqlang/jq` cannot be satisfied by `https://github.com/jqlang/jq-evil/...` and `https://dl.example.com/` cannot be satisfied by `https://dl.example.com.evil.net/...`. `trace` returns each link's artifact and list URL for the same reason.
4. **`lookup(digest)`** answers "has anyone attested a file with this sha256?" and returns up to ten attestation ids.

The checksum list is read as GNU `sha256sum` output: `<64 hex digits>  <name>` or `<64 hex digits> *<name>`, with an optional leading `./` on the name. Anything else on a line is ignored.

## Live on Bradbury

Contract: `0x6508856DE231e094BfD121Eb5A30D5C3c03972A9`

An earlier build, `0x9985c1d3cf118Aa8a1D930a9b3635e81606108F5`, produced the logs numbered 01 to 08. It differs only in the trust views (`is_trusted_from` and the URLs in `trace` were added after a self-review); the `check` path is identical. Log 09 is from the current contract.

Real data: the jq 1.7.1 release (`jqlang/jq`). Every checksum below is the publisher's own, and validators computed the same digest independently.

| Case | What it shows | Result |
|---|---|---|
| root `jq-1.7.1.tar.gz` (1,950,645 bytes) against `sha256sum.txt` | a real source tarball hashed by validators | `verified`, digest `478c9ca1...80c2` |
| child `jq-linux-amd64` (2,319,424 bytes), parent = the tarball | a build bound to its source by the same list | `verified`, `is_trusted` true, `trace` returns both links |
| `jq-linux-arm64` bytes under the name `jq-linux-amd64` | the wrong file served under a listed name | `mismatch` (listed `5942c9b0...`), not trusted |
| a filename the list never mentions | silence is not a pass | `unlisted`, not trusted |
| `bat-v0.26.1-x86_64-pc-windows-msvc.zip` (3,613,318 bytes) | a large artifact fits under the gas cap | `verified` (list is `demo/BATSUMS`, so this checks size, not the publisher) |
| `yq_linux_arm64.tar.gz` (5,146,133 bytes) | over the 4,000,000 byte limit | `check` reverts, nothing recorded (leader output `too_large`) |
| an artifact URL that returns 404 | an error is not a verdict | `check` reverts, nothing recorded (leader output `unreachable`) |
| a second `check` seconds after the first | rate limit | reverts before reading anything |

Then a demo chain whose publisher is this repository, so every state can be provoked on purpose (`demo/`):

| Step | Result |
|---|---|
| root `src-1.0.txt` against `demo/SHA256SUMS` | `verified` |
| child `build-1.0.txt`, parent = root, same list | `verified`, `is_trusted` true |
| `orphan.txt` matches its own list `OTHERSUMS`, but that list never mentions the root | `unbound`, not trusted |
| the root file is edited after attestation, then re-checked | root `drifted`, `last_digest` shows the new bytes, the committed digest is kept |
| ask about the untouched child again | `is_trusted` false: the root above it is no longer verified |

Publisher pinning, on the current contract (log 09). A third party's list (`demo/MIRRORSUMS`) vouches for the real `jq-linux-amd64` with the real tarball as its parent, so that chain is genuinely consistent:

| Question | `is_trusted` | `is_trusted_from(.../jqlang/jq/releases/)` |
|---|---|---|
| the chain vouched for by jq's own list | true | true |
| the same binary vouched for by the third party's list | true | **false** |
| the jq chain, pinned to some other publisher | | false |
| a prefix with no trailing slash | | false |

Transactions and the full command output are in [`logs/`](logs). To reproduce:

```
npm install
LINEAGE=0x6508856DE231e094BfD121Eb5A30D5C3c03972A9 node scripts/live.mjs attest <artifactUrl> <manifestUrl> <filename> [parentId]
LINEAGE=... node scripts/live.mjs check <attestationId>
LINEAGE=... node scripts/live.mjs trace <attestationId>
LINEAGE=... node scripts/live.mjs trusted <attestationId> [maxAgeSeconds]
LINEAGE=... node scripts/live.mjs trustedfrom <attestationId> <maxAgeSeconds> <manifestPrefix>
LINEAGE=... node scripts/live.mjs lookup <sha256>
```

## Security model

- **An error is never a verdict.** A failed connection, a timeout, a non-200 status or an empty body on either the artifact or the list reverts `check()` and records nothing. Otherwise anyone able to make validators' requests fail could forge a `mismatch` or `unlisted` record.
- **Oversized sources record nothing either.** Artifacts above 4,000,000 bytes and lists above 500,000 bytes are refused rather than half-read. Bradbury also has a per-transaction gas cap, so this is a real limit, not a style choice.
- **The digest is computed, never claimed.** The leader's result is only accepted if validators, each hashing the bytes themselves, produce the same verdict, computed digest, listed digest and size. A leader that lies about any one of them is rejected. In direct-mode tests this field-by-field agreement cannot be exercised, so it is the one rule not covered by a failing test.
- **Matching is exact.** The filename must equal a name in the list (no substring, no case folding). Digests are 64 hex characters, lower-cased before comparing. Lines that are not exactly `<digest> <name>` vouch for nothing, including very long lines (over 1,000 characters are skipped). A list that names the same file with two different digests is a `mismatch`, never "pick one".
- **The parent binding is part of the verdict.** A child is `verified` only if the list that vouches for it also names the parent's committed digest. A child cannot be checked at all until its parent is `verified`, and that holds on every re-check, not only the first.
- **History is not rewritten.** The first verified digest is committed and indexed. If the bytes or the list later change, the attestation becomes `drifted` and records the new digest in `last_digest`, but the committed digest stays. Restoring the original bytes returns it to `verified`.
- **Trust ages and can be pinned to a publisher.** `is_trusted` and `is_trusted_from` can require every link to have been checked recently, so a consumer is not relying on a months-old `verified`, and `is_trusted_from` requires every link's list to sit under the consumer's chosen prefix, so a self-consistent chain on someone else's site does not pass. Neither reverts on bad input.
- **Validators can't be aimed inward.** URLs must be `https`, a real domain name (no IP address, port, credentials, internal suffix or single-label host), at most 300 characters, and without `|`.
- **Checks are rate limited** to one per attestation per five minutes, and a failed read doesn't start the clock.
- **Listings are bounded.** `get_ids(offset, limit)` returns at most 50 ids, `lookup` at most 10, and chains are at most 9 links.

### What Lineage does not do

- **The "derived from" edge is vouched for by the publisher's list, not proven.** Lineage checks that a single checksum list names both the parent and the child. It does not and cannot show that the child was actually compiled from the parent. It prevents a stranger from claiming a lineage the publisher never wrote down.
- **It trusts the publisher's list.** If the publisher is compromised and both the file and the list are replaced consistently, the first attestation is whatever was served at the time. Lineage makes later silent replacement visible (`drifted`), it does not make the first publication honest.
- **Attest immutable URLs.** An attestation is one (artifact URL, list URL, filename, parent), and it can be registered once. If the bytes behind a URL change, the attestation goes `drifted` and stays so, and the same tuple cannot be registered again. Publish the new version under a new URL (release assets and commit-pinned URLs are naturally this way) and attest that. Attesting a "latest" URL gives you a drift alarm, not a stable record.
- **Filenames are limited** to letters, digits and `. _ + @ = , - ~`. A file whose name contains a space cannot be attested.
- **`lookup` is a history, not a gate.** It lists attestations that were once verified with a digest, including ones that have since drifted, and including ones vouched for by anyone's list. Read `status` and `manifest_url` from the result, or gate on `is_trusted_from`.
- **It fails closed on large files.** Anything over 4 MB cannot be attested, so this covers source tarballs and single binaries, not container images or installers of hundreds of megabytes.
- Someone has to call `check()`. A consumer should require recent checks through the age argument of `is_trusted`.
- Redirects are followed by the platform's fetcher and are not inspected, and hostnames are filtered by name only (a public name that resolves to a private address is not caught).
- GitHub's raw host caches for about five minutes, so a demo edit takes that long to become visible to a re-check.

### Testing

59 direct-mode tests cover validation, id derivation, every verdict, list formats, unreadable and oversized sources, rate limiting, drift and restore, parent binding, trace and trust (including tainting, age, and publisher pinning with lookalike hosts), lookup and paging.

Every rule was mutation-checked: 73 deliberate breakages of the contract, 70 caught by a test. The three survivors:

- 1 survivor is the validator-agreement check ("validators ignore the digest"), which direct mode cannot exercise because there is only one validator.
- 2 survivors are defensive guards that cannot be triggered through the public methods: the loop bound in `trace` and the root-has-no-parent check in `is_trusted`. Attestations can only name an existing parent, so chains are acyclic and at most 9 long by construction. They stay as a second line of defense.

The first mutation run left 10 survivors. Seven were real gaps (a huge line vouching for a parent, a re-check of an unlisted child skipping the parent rule, an artifact or list returning a failing status individually, a consistent rewrite of both file and list, and the refusal message for credentials or ports) and each now has a test. Two guards added with `is_trusted_from` (the prefix must start with `https://`, and be at most 300 characters) also survived, because no stored URL can match such a prefix anyway, so they were deleted instead of tested.

## Layout

- `contracts/lineage.py` the contract (about 12 KB, safely under the Bradbury gas cap)
- `tests/direct/` direct-mode tests
- `scripts/live.mjs` helper for the live network
- `demo/` the artifacts and checksum lists the live demo uses
- `logs/` output of the live runs

## License

MIT
