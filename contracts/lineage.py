# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from genlayer import *

MAX_URL = 300
MAX_NAME = 200
MAX_BYTES = 4_000_000  # largest artifact a check will hash
MAX_MANIFEST = 500_000
MAX_DEPTH = 8
PAGE = 50
MIN_RECHECK = 300  # seconds between recorded checks of one attestation
HEADERS = {"Accept": "application/octet-stream,text/plain,*/*", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
LABEL = "abcdefghijklmnopqrstuvwxyz0123456789-"
NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+@=,-~"
INTERNAL = ("local", "internal", "lan", "localhost", "home", "corp", "intranet", "localdomain", "arpa")
ENTRY = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?(.+)$")

PENDING = "pending"  # registered, never checked
VERIFIED = "verified"  # computed digest equals the publisher's listed digest (and the list vouches for the parent)
MISMATCH = "mismatch"  # the publisher lists a different digest, or lists the name twice with different digests
UNLISTED = "unlisted"  # the publisher's list does not name this file
UNBOUND = "unbound"  # file matches, but the list does not also vouch for the parent
DRIFTED = "drifted"  # was verified, and now the bytes or the list say something else


def _bad(c: bool, m: str) -> None:
    if c:
        raise gl.vm.UserError(m)


def _url(u) -> str:
    _bad(not isinstance(u, str) or not u.startswith("https://") or len(u) > MAX_URL, f"url must be https, at most {MAX_URL} characters")
    for ch in u:
        _bad(ch.isspace() or ch in "\"'<>\\`|", "url has a forbidden character")
    h = u[8:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].lower()
    _bad("@" in h or ":" in h, "url may not have credentials or a port")
    p = h.split(".")
    _bad(len(p) < 2 or p[-1] in INTERNAL or not any(c.isalpha() for c in p[-1]), "url host must be a public domain name")
    for x in p:
        _bad(not 1 <= len(x) <= 63 or x[0] == "-" or x[-1] == "-" or any(c not in LABEL for c in x), "invalid url host")
    return u.split("#", 1)[0]


def _name(n) -> str:
    _bad(not isinstance(n, str) or not 1 <= len(n) <= MAX_NAME, f"filename must be 1 to {MAX_NAME} characters")
    _bad(any(c not in NAME_CHARS for c in n) or n[0] == ".", "filename may use letters, digits and . _ + @ = , - ~ only")
    return n


def _id(artifact: str, manifest: str, name: str, parent: str) -> str:
    """One attestation is one (artifact, list, name, parent). The fields are joined with '|', which none may contain."""
    return hashlib.sha256(f"{artifact}|{manifest}|{name}|{parent}".encode("utf-8")).hexdigest()


def _entries(text: str) -> list:
    """Every (digest, name) line of a checksum list. Lines that are not exactly '<64 hex digits> <name>' are ignored."""
    out = []
    for line in text.split("\n"):
        m = ENTRY.match(line.rstrip()) if len(line) <= 1000 else None
        if m:
            n = m.group(2)
            out.append((m.group(1).lower(), n[2:] if n.startswith("./") else n))
    return out


def _judge(artifact_digest: str, entries: list, name: str, parent_digest: str) -> dict:
    """The deterministic verdict on one artifact against its publisher's list."""
    listed = sorted({d for d, n in entries if n == name})
    if not listed:
        return {"kind": UNLISTED, "listed": ""}
    if len(listed) > 1:
        return {"kind": MISMATCH, "listed": ""}
    if listed[0] != artifact_digest:
        return {"kind": MISMATCH, "listed": listed[0]}
    if parent_digest != "" and parent_digest not in {d for d, _ in entries}:
        return {"kind": UNBOUND, "listed": listed[0]}
    return {"kind": VERIFIED, "listed": listed[0]}


@allow_storage
@dataclass
class Attestation:
    attester: Address
    artifact_url: str
    manifest_url: str
    filename: str
    parent: str
    depth: u256
    status: str
    digest: str
    listed: str
    last_digest: str
    size: u256
    created_at: u256
    first_verified_at: u256
    checked_at: u256
    checks: u256


class Lineage(gl.Contract):
    atts: TreeMap[str, Attestation]
    ids: DynArray[str]
    by_digest: TreeMap[str, DynArray[str]]

    def __init__(self):
        pass

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _get(self, i: str) -> Attestation:
        _bad(not isinstance(i, str) or i not in self.atts, "Attestation not found")
        return self.atts[i]

    @gl.public.write
    def attest(self, artifact_url: str, manifest_url: str, filename: str, parent_id: str) -> None:
        a, m, n = _url(artifact_url), _url(manifest_url), _name(filename)
        _bad(not isinstance(parent_id, str) or "|" in parent_id, "parent_id must be text")
        i = _id(a, m, n, parent_id)
        _bad(i in self.atts, "Attestation already exists")
        depth = 0
        if parent_id != "":
            depth = int(self._get(parent_id).depth) + 1
            _bad(depth > MAX_DEPTH, f"A chain can be at most {MAX_DEPTH + 1} attestations long")
        self.atts[i] = Attestation(
            attester=gl.message.sender_address, artifact_url=a, manifest_url=m, filename=n, parent=parent_id, depth=depth,
            status=PENDING, digest="", listed="", last_digest="", size=0, created_at=self._now(), first_verified_at=0, checked_at=0, checks=0,
        )
        self.ids.append(i)

    def _read(self, artifact_url: str, manifest_url: str, name: str, parent_digest: str) -> dict:
        def leader_fn() -> dict:
            try:
                art = gl.nondet.web.request(artifact_url, method="GET", headers=HEADERS)
                man = gl.nondet.web.request(manifest_url, method="GET", headers=HEADERS)
            except Exception:
                return {"kind": "unreachable", "digest": "", "listed": "", "size": 0}
            if art.status != 200 or man.status != 200 or not art.body or not man.body:
                return {"kind": "unreachable", "digest": "", "listed": "", "size": 0}
            if len(art.body) > MAX_BYTES or len(man.body) > MAX_MANIFEST:
                return {"kind": "too_large", "digest": "", "listed": "", "size": len(art.body)}
            digest = hashlib.sha256(art.body).hexdigest()
            v = _judge(digest, _entries(man.body.decode("utf-8", errors="replace")), name, parent_digest)
            return {"kind": v["kind"], "digest": digest, "listed": v["listed"], "size": len(art.body)}

        def validator_fn(res) -> bool:
            if not isinstance(res, gl.vm.Return):
                return False
            t = res.calldata
            if not isinstance(t, dict) or any(not isinstance(t.get(k), str) for k in ("kind", "digest", "listed")) or not isinstance(t.get("size"), int):
                return False
            m = leader_fn()
            return all(m[k] == t[k] for k in ("kind", "digest", "listed", "size"))

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

    @gl.public.write
    def check(self, attestation_id: str) -> None:
        """Validators hash the artifact and agree on what its publisher's list says. Unreadable or oversized sources record nothing."""
        a = self._get(attestation_id)
        now = self._now()
        _bad(a.checked_at > 0 and now < int(a.checked_at) + MIN_RECHECK, "Checked too recently, try again later")
        parent_digest = ""
        if a.parent != "":
            p = self._get(a.parent)
            _bad(a.digest == "" and p.status != VERIFIED, "The parent is not verified yet")
            parent_digest = p.digest
        r = self._read(a.artifact_url, a.manifest_url, a.filename, parent_digest)
        _bad(r["kind"] == "unreachable", "Source unreadable, nothing recorded. Try again shortly.")
        _bad(r["kind"] == "too_large", f"Artifact or list too large (artifact at most {MAX_BYTES} bytes), nothing recorded")
        a.checked_at = now
        a.checks += 1
        a.size = r["size"]
        a.listed = r["listed"]
        if a.digest == "":
            a.status = r["kind"]
            if r["kind"] == VERIFIED:
                a.digest = r["digest"]
                a.first_verified_at = now
                self.by_digest.get_or_insert_default(r["digest"]).append(attestation_id)
        elif r["kind"] == VERIFIED and r["digest"] == a.digest:
            a.status = VERIFIED
            a.last_digest = ""
        else:
            a.status = DRIFTED
            a.last_digest = r["digest"]

    @gl.public.view
    def attestation_id(self, artifact_url: str, manifest_url: str, filename: str, parent_id: str) -> str:
        return _id(_url(artifact_url), _url(manifest_url), _name(filename), parent_id)

    @gl.public.view
    def get_attestation(self, attestation_id: str) -> dict:
        a = self._get(attestation_id)
        return {
            "attester": a.attester.as_hex, "artifact_url": a.artifact_url, "manifest_url": a.manifest_url, "filename": a.filename,
            "parent": a.parent, "depth": a.depth, "status": a.status, "digest": a.digest, "listed": a.listed, "last_digest": a.last_digest,
            "size": a.size, "created_at": a.created_at, "first_verified_at": a.first_verified_at, "checked_at": a.checked_at, "checks": a.checks,
        }

    @gl.public.view
    def trace(self, attestation_id: str) -> list:
        """The chain from this attestation up to its root, nearest first."""
        out = []
        cur = attestation_id
        while isinstance(cur, str) and cur in self.atts and len(out) <= MAX_DEPTH:
            a = self.atts[cur]
            out.append({"id": cur, "filename": a.filename, "status": a.status, "digest": a.digest, "checked_at": a.checked_at,
                        "artifact_url": a.artifact_url, "manifest_url": a.manifest_url})
            cur = a.parent
        return out

    def _trusted(self, attestation_id: str, max_check_age_seconds: int, prefix: str) -> bool:
        if isinstance(max_check_age_seconds, bool) or not isinstance(max_check_age_seconds, int) or max_check_age_seconds < 0:
            return False
        chain = self.trace(attestation_id)
        if not chain or self.atts[chain[-1]["id"]].parent != "":
            return False
        now = self._now()
        for n in chain:
            if n["status"] != VERIFIED or (max_check_age_seconds > 0 and now > int(n["checked_at"]) + max_check_age_seconds):
                return False
            if prefix != "" and not n["manifest_url"].startswith(prefix):
                return False
        return True

    @gl.public.view
    def is_trusted(self, attestation_id: str, max_check_age_seconds: int) -> bool:
        """True only if this attestation and every ancestor is verified and, when an age is given, was checked that recently.
        Anyone can publish a self-consistent chain on their own site, so a consumer that cares who vouched should use is_trusted_from."""
        return self._trusted(attestation_id, max_check_age_seconds, "")

    @gl.public.view
    def is_trusted_from(self, attestation_id: str, max_check_age_seconds: int, manifest_prefix: str) -> bool:
        """is_trusted, and every link's checksum list must live under manifest_prefix (ending in '/', e.g. a project's release path)."""
        if not isinstance(manifest_prefix, str) or not manifest_prefix.endswith("/"):
            return False
        return self._trusted(attestation_id, max_check_age_seconds, manifest_prefix)

    @gl.public.view
    def lookup(self, digest: str) -> list:
        """Attestation ids that verified this sha256 (at most 10)."""
        if not isinstance(digest, str) or digest.lower() not in self.by_digest:
            return []
        arr = self.by_digest[digest.lower()]
        return [arr[k] for k in range(min(10, len(arr)))]

    @gl.public.view
    def get_count(self) -> int:
        return len(self.ids)

    @gl.public.view
    def get_ids(self, offset: int, limit: int) -> list:
        """At most 50 ids, oldest first. Never reverts."""
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            return []
        return [self.ids[k] for k in range(offset, min(offset + min(limit, PAGE), len(self.ids)))]
