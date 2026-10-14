"""Direct-mode tests for Lineage (digest attestations with chains of custody)."""

import hashlib

import pytest

CONTRACT = "contracts/lineage.py"
T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-01T00:06:00Z"  # past the 5 minute recheck gap
T2 = "2026-01-01T00:12:00Z"
T3 = "2026-01-01T02:00:00Z"
MAX_BYTES = 4_000_000

SRC_URL = "https://dl.example.com/app-1.0.tar.gz"
BIN_URL = "https://dl.example.com/app-linux-amd64"
MAN_URL = "https://dl.example.com/SHA256SUMS"
SRC = b"source code, version 1"
BIN = b"compiled binary, version 1"


def _d(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _man(*pairs, star=False, nl="\n"):
    return nl.join(f"{d} {'*' if star else ' '}{n}" for d, n in pairs)


STD_MAN = _man((_d(SRC), "app-1.0.tar.gz"), (_d(BIN), "app-linux-amd64"))


def _serve(vm, files: dict, status: int = 200):
    vm.clear_mocks()
    for url, body in files.items():
        vm.mock_web("^" + url.replace(".", r"\.") + "$", {"method": "GET", "status": status, "body": body})


def _std(vm, src=SRC, binary=BIN, man=STD_MAN):
    _serve(vm, {SRC_URL: src, BIN_URL: binary, MAN_URL: man})


def _att(c, artifact=SRC_URL, name="app-1.0.tar.gz", parent="", manifest=MAN_URL):
    c.attest(artifact, manifest, name, parent)
    return c.attestation_id(artifact, manifest, name, parent)


def _root(vm, c):
    i = _att(c)
    c.check(i)
    return i


# ---------------------------------------------------------------------------
# attest: validation, ids, chains
# ---------------------------------------------------------------------------


def test_attest_stores_a_pending_attestation(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    direct_vm.sender = direct_alice
    i = _att(c)
    a = c.get_attestation(i)
    assert (a["status"], a["digest"], a["checks"], a["depth"], a["parent"]) == ("pending", "", 0, 0, "")
    assert (a["artifact_url"], a["manifest_url"], a["filename"]) == (SRC_URL, MAN_URL, "app-1.0.tar.gz")
    assert c.get_count() == 1 and c.get_ids(0, 10) == [i]
    assert len(i) == 64


def test_the_id_depends_on_every_field_and_ignores_url_fragments(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    base = c.attestation_id(SRC_URL, MAN_URL, "app-1.0.tar.gz", "")
    assert base == c.attestation_id(SRC_URL + "#frag", MAN_URL, "app-1.0.tar.gz", "")
    others = {
        c.attestation_id(BIN_URL, MAN_URL, "app-1.0.tar.gz", ""),
        c.attestation_id(SRC_URL, "https://dl.example.com/OTHERSUMS", "app-1.0.tar.gz", ""),
        c.attestation_id(SRC_URL, MAN_URL, "app-1.1.tar.gz", ""),
        c.attestation_id(SRC_URL, MAN_URL, "app-1.0.tar.gz", base),
    }
    assert base not in others and len(others) == 4


def test_duplicates_are_refused_and_different_rules_are_separate_attestations(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _att(c)
    with direct_vm.expect_revert("already exists"):
        _att(c)
    _att(c, manifest="https://dl.example.com/OTHERSUMS")
    assert c.get_count() == 2


def test_urls_the_validators_must_not_be_aimed_at_are_refused(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    bad = ["http://dl.example.com/a", "https://127.0.0.1/a", "https://localhost/a", "https://dl.example.com:8080/a",
           "https://u:p@dl.example.com/a", "https://printer.local/a", "https://nodots/a", "https://exa mple.com/a",
           "https://dl.example.com/a|b", "https://dl.example.com/" + "a" * 300, "https://-bad.example.com/a", ""]
    for u in bad:
        with direct_vm.expect_revert():
            c.attest(u, MAN_URL, "app.tar.gz", "")
        with direct_vm.expect_revert():
            c.attest(SRC_URL, u, "app.tar.gz", "")


def test_filenames_are_restricted(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    for n in ("", "a" * 201, "has space", "dir/file", "back\\slash", ".hidden", "pipe|name", "line\nbreak", "café"):
        with direct_vm.expect_revert():
            c.attest(SRC_URL, MAN_URL, n, "")
    for n in ("app-1.0.tar.gz", "a_b+c@d=e,f-g~h.zip", "A" * 200):
        c.attest(SRC_URL, MAN_URL, n, "")


def test_an_unknown_parent_is_refused(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    with direct_vm.expect_revert("not found"):
        c.attest(BIN_URL, MAN_URL, "app-linux-amd64", "0" * 64)


def test_a_chain_has_a_depth_limit(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    parent = ""
    for k in range(9):  # depths 0 to 8
        parent = _att(c, name=f"file{k}.bin", parent=parent)
    assert c.get_attestation(parent)["depth"] == 8
    with direct_vm.expect_revert("at most 9"):
        c.attest(BIN_URL, MAN_URL, "file9.bin", parent)


# ---------------------------------------------------------------------------
# check: the verdicts
# ---------------------------------------------------------------------------


def test_a_matching_artifact_is_verified_and_committed(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    i = _root(direct_vm, c)
    a = c.get_attestation(i)
    assert a["status"] == "verified" and a["digest"] == _d(SRC) and a["listed"] == _d(SRC)
    assert a["size"] == len(SRC) and a["checks"] == 1 and a["first_verified_at"] > 0 and a["checked_at"] == a["first_verified_at"]
    assert c.lookup(_d(SRC)) == [i]


def test_check_is_permissionless(direct_vm, direct_deploy, direct_alice, direct_charlie):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    direct_vm.sender = direct_alice
    i = _att(c)
    direct_vm.sender = direct_charlie
    c.check(i)
    assert c.get_attestation(i)["status"] == "verified"


def test_a_different_digest_in_the_publishers_list_is_a_mismatch(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, src=b"tampered source")
    i = _att(c)
    c.check(i)
    a = c.get_attestation(i)
    assert a["status"] == "mismatch" and a["digest"] == "" and a["listed"] == _d(SRC)
    assert c.lookup(_d(b"tampered source")) == []  # a mismatch is never indexed as trusted


def test_a_file_the_list_does_not_name_is_unlisted(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=_man((_d(BIN), "app-linux-amd64")))
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "unlisted"


def test_a_list_that_contradicts_itself_is_a_mismatch(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=_man((_d(SRC), "app-1.0.tar.gz"), (_d(b"other"), "app-1.0.tar.gz")))
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "mismatch"


def test_the_same_entry_twice_is_fine(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=_man((_d(SRC), "app-1.0.tar.gz"), (_d(SRC), "app-1.0.tar.gz")))
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "verified"


@pytest.mark.parametrize("manifest", [
    _man((_d(SRC).upper(), "app-1.0.tar.gz")),                                   # upper-case hex
    _man((_d(SRC), "app-1.0.tar.gz"), star=True),                                # binary-mode marker
    _man((_d(SRC), "./app-1.0.tar.gz")),                                         # leading ./
    _man((_d(BIN), "app-linux-amd64"), (_d(SRC), "app-1.0.tar.gz"), nl="\r\n"),  # Windows line endings
    "# release checksums\n\nnot a checksum line\n" + _man((_d(SRC), "app-1.0.tar.gz")) + "\n\n",
    "x" * 1100 + "\n" + _man((_d(SRC), "app-1.0.tar.gz")),                       # an over-long junk line is ignored
])
def test_common_checksum_list_formats_are_accepted(direct_vm, direct_deploy, manifest):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=manifest)
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "verified"


@pytest.mark.parametrize("line", [
    _d(SRC)[:63] + "  app-1.0.tar.gz",        # 63 hex digits
    _d(SRC) + "0  app-1.0.tar.gz",           # 65 hex digits
    _d(SRC) + "app-1.0.tar.gz",              # no separator
    "zz" + _d(SRC)[2:] + "  app-1.0.tar.gz",  # not hex
    "  " + _d(SRC) + "  app-1.0.tar.gz",     # indented: not a checksum line
])
def test_malformed_checksum_lines_vouch_for_nothing(direct_vm, direct_deploy, line):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=line)
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "unlisted"


def test_the_name_must_match_exactly(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, man=_man((_d(SRC), "xapp-1.0.tar.gz"), (_d(SRC), "app-1.0.tar.gz.sig"), (_d(SRC), "APP-1.0.TAR.GZ")))
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "unlisted"


def test_unreadable_sources_record_nothing(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    i = _att(c)
    cases = [
        ({SRC_URL: SRC, MAN_URL: STD_MAN}, 404),
        ({SRC_URL: SRC, MAN_URL: STD_MAN}, 503),
        ({SRC_URL: b"", MAN_URL: STD_MAN}, 200),
        ({SRC_URL: SRC, MAN_URL: ""}, 200),
    ]
    for files, status in cases:
        _serve(direct_vm, files, status)
        with direct_vm.expect_revert("unreadable"):
            c.check(i)
    _serve(direct_vm, {SRC_URL: SRC})  # the list is simply not served
    with direct_vm.expect_revert("unreadable"):
        c.check(i)
    a = c.get_attestation(i)
    assert (a["status"], a["checks"], a["checked_at"], a["digest"]) == ("pending", 0, 0, "")


def test_oversized_sources_record_nothing(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    i = _att(c)
    _serve(direct_vm, {SRC_URL: b"x" * (MAX_BYTES + 1), MAN_URL: STD_MAN})
    with direct_vm.expect_revert("too large"):
        c.check(i)
    _serve(direct_vm, {SRC_URL: SRC, MAN_URL: "a" * 500_001})
    with direct_vm.expect_revert("too large"):
        c.check(i)
    assert c.get_attestation(i)["checks"] == 0
    _serve(direct_vm, {SRC_URL: b"x" * MAX_BYTES, MAN_URL: STD_MAN})  # exactly the limit is hashed
    c.check(i)
    assert c.get_attestation(i)["checks"] == 1


def test_a_recorded_failure_can_later_become_verified(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm, src=b"wrong bytes")
    i = _att(c)
    c.check(i)
    assert c.get_attestation(i)["status"] == "mismatch"
    direct_vm.warp(T1)
    _std(direct_vm)
    c.check(i)
    a = c.get_attestation(i)
    assert a["status"] == "verified" and a["digest"] == _d(SRC) and a["checks"] == 2


def test_checks_are_rate_limited_and_a_failed_read_does_not_start_the_clock(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    i = _att(c)
    _serve(direct_vm, {SRC_URL: SRC}, 404)
    with direct_vm.expect_revert("unreadable"):
        c.check(i)
    _std(direct_vm)
    c.check(i)  # immediately after a failed read is fine
    with direct_vm.expect_revert("too recently"):
        c.check(i)
    direct_vm.warp("2026-01-01T00:04:59Z")
    with direct_vm.expect_revert("too recently"):
        c.check(i)
    direct_vm.warp("2026-01-01T00:05:00Z")
    c.check(i)
    assert c.get_attestation(i)["checks"] == 2


def test_unknown_ids_revert(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    with direct_vm.expect_revert("not found"):
        c.check("0" * 64)
    with direct_vm.expect_revert("not found"):
        c.get_attestation("nope")


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------


def test_changed_bytes_after_verification_are_drift_and_the_committed_digest_stays(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    i = _root(direct_vm, c)
    direct_vm.warp(T1)
    _std(direct_vm, src=b"silently replaced")
    c.check(i)
    a = c.get_attestation(i)
    assert a["status"] == "drifted" and a["digest"] == _d(SRC) and a["last_digest"] == _d(b"silently replaced")
    assert a["first_verified_at"] > 0 and c.lookup(_d(SRC)) == [i]  # history is not rewritten


def test_a_changed_list_after_verification_is_drift(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    i = _root(direct_vm, c)
    for k, man in enumerate((_man((_d(b"another"), "app-1.0.tar.gz")), _man((_d(BIN), "app-linux-amd64")))):
        direct_vm.warp(["2026-01-01T00:06:00Z", "2026-01-01T00:12:00Z"][k])
        _std(direct_vm, man=man)
        c.check(i)
        assert c.get_attestation(i)["status"] == "drifted"


def test_restoring_the_bytes_restores_verified(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    i = _root(direct_vm, c)
    direct_vm.warp(T1)
    _std(direct_vm, src=b"changed")
    c.check(i)
    assert c.get_attestation(i)["status"] == "drifted"
    direct_vm.warp(T2)
    _std(direct_vm)
    c.check(i)
    a = c.get_attestation(i)
    assert a["status"] == "verified" and a["last_digest"] == "" and a["checks"] == 3


# ---------------------------------------------------------------------------
# chains of custody
# ---------------------------------------------------------------------------


def test_a_child_cannot_be_verified_before_its_parent(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _att(c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    with direct_vm.expect_revert("parent is not verified"):
        c.check(child)  # the parent is still pending
    _std(direct_vm, src=b"wrong")
    c.check(root)
    assert c.get_attestation(root)["status"] == "mismatch"
    with direct_vm.expect_revert("parent is not verified"):
        c.check(child)  # a mismatched parent does not count either


def test_a_child_whose_list_also_vouches_for_the_parent_is_verified(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    a = c.get_attestation(child)
    assert a["status"] == "verified" and a["parent"] == root and a["depth"] == 1 and a["digest"] == _d(BIN)


def test_a_child_whose_list_does_not_vouch_for_the_parent_is_unbound(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    other = "https://dl.example.com/ONLYBIN"
    _serve(direct_vm, {SRC_URL: SRC, BIN_URL: BIN, MAN_URL: STD_MAN, other: _man((_d(BIN), "app-linux-amd64"))})
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root, manifest=other)
    c.check(child)
    assert c.get_attestation(child)["status"] == "unbound"
    assert c.get_attestation(child)["digest"] == ""  # not committed, not indexed, not trusted
    assert c.lookup(_d(BIN)) == []
    assert c.is_trusted(child, 0) is False


def test_an_unbound_child_cannot_become_verified_while_its_parent_is_unverified(direct_vm, direct_deploy):
    """A re-check must not skip the parent binding just because the parent has no committed digest yet."""
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _att(c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    _std(direct_vm, src=b"wrong")
    c.check(root)  # the parent is a mismatch
    _std(direct_vm)
    with direct_vm.expect_revert("parent is not verified"):
        c.check(child)
    assert c.get_attestation(child)["status"] == "pending"


def test_a_verified_child_keeps_binding_to_the_parents_committed_digest_after_the_parent_drifts(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    direct_vm.warp(T1)
    _std(direct_vm, src=b"replaced upstream")
    c.check(root)
    assert c.get_attestation(root)["status"] == "drifted"
    direct_vm.warp(T2)
    c.check(child)  # the child's own list still vouches for the digest the root was verified with
    assert c.get_attestation(child)["status"] == "verified"


def test_trace_walks_up_to_the_root_nearest_first(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    t = c.trace(child)
    assert [n["id"] for n in t] == [child, root]
    assert [n["status"] for n in t] == ["verified", "verified"]
    assert [n["filename"] for n in t] == ["app-linux-amd64", "app-1.0.tar.gz"]
    assert c.trace(root) == [t[1]] and c.trace("unknown") == [] and c.trace(7) == []


# ---------------------------------------------------------------------------
# trust
# ---------------------------------------------------------------------------


def test_trust_requires_every_link_to_be_verified(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    assert c.is_trusted(child, 0) is False  # pending
    c.check(child)
    assert c.is_trusted(root, 0) is True and c.is_trusted(child, 0) is True


def test_a_drifted_ancestor_taints_everything_built_from_it(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    direct_vm.warp(T1)
    _std(direct_vm, src=b"upstream compromised")
    c.check(root)
    assert c.get_attestation(child)["status"] == "verified"  # the child itself is untouched
    assert c.is_trusted(child, 0) is False  # but it is no longer trusted
    assert c.is_trusted(root, 0) is False


def test_trust_can_require_a_recent_check(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    direct_vm.warp(T3)  # almost two hours later
    assert c.is_trusted(root, 0) is True  # no age asked for
    assert c.is_trusted(root, 3600) is False
    assert c.is_trusted(root, 7200) is True
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    assert c.is_trusted(child, 3600) is False  # the root's own check is too old


def test_trust_never_reverts_on_bad_input(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    for bad in (-1, True, "3600", None):
        assert c.is_trusted(root, bad) is False
    assert c.is_trusted("unknown", 0) is False and c.is_trusted(5, 0) is False


def test_a_three_level_chain(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    third = "https://dl.example.com/app-container.tar"
    third_bytes = b"container image layers"
    man = _man((_d(SRC), "app-1.0.tar.gz"), (_d(BIN), "app-linux-amd64"), (_d(third_bytes), "app-container.tar"))
    _serve(direct_vm, {SRC_URL: SRC, BIN_URL: BIN, third: third_bytes, MAN_URL: man})
    root = _root(direct_vm, c)
    mid = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(mid)
    leaf = _att(c, artifact=third, name="app-container.tar", parent=mid)
    c.check(leaf)
    assert [n["filename"] for n in c.trace(leaf)] == ["app-container.tar", "app-linux-amd64", "app-1.0.tar.gz"]
    assert c.is_trusted(leaf, 0) is True


# ---------------------------------------------------------------------------
# lookup and paging
# ---------------------------------------------------------------------------


def test_lookup_finds_attestations_by_digest(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    a = _root(direct_vm, c)
    mirror = "https://mirror.example.org/SHA256SUMS"
    _serve(direct_vm, {SRC_URL: SRC, mirror: STD_MAN})
    b = _att(c, manifest=mirror)
    c.check(b)
    assert sorted(c.lookup(_d(SRC))) == sorted([a, b])  # two independent publishers vouch for the same bytes
    assert c.lookup(_d(SRC).upper()) == c.lookup(_d(SRC))
    assert c.lookup(_d(b"nobody vouched for this")) == [] and c.lookup(5) == [] and c.lookup("") == []


def test_lookup_is_capped(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _serve(direct_vm, {SRC_URL: SRC, MAN_URL: STD_MAN})
    for k in range(12):
        _serve(direct_vm, {SRC_URL: SRC, f"https://m{k}.example.org/SUMS": STD_MAN})
        i = _att(c, manifest=f"https://m{k}.example.org/SUMS")
        c.check(i)
    assert len(c.lookup(_d(SRC))) == 10


def test_ids_are_paged_and_capped(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    made = [_att(c, name=f"file{k}.bin") for k in range(55)]
    assert c.get_count() == 55 and len(c.get_ids(0, 1000)) == 50
    assert c.get_ids(50, 50) == made[50:] and c.get_ids(0, 2) == made[:2]
    assert c.get_ids(99, 5) == [] and c.get_ids(-1, 5) == [] and c.get_ids(0, 0) == [] and c.get_ids(True, 3) == []


# ---------------------------------------------------------------------------
# gaps found by mutation testing
# ---------------------------------------------------------------------------


def test_credentials_and_ports_are_refused_with_a_clear_reason(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    for u in ("https://user@dl.example.com/a", "https://dl.example.com:8443/a"):
        with direct_vm.expect_revert("credentials or a port"):
            c.attest(u, MAN_URL, "app.tar.gz", "")


@pytest.mark.parametrize("bad", ["artifact", "list"])
def test_a_failing_status_on_either_source_records_nothing(direct_vm, direct_deploy, bad):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    i = _att(c)
    direct_vm.clear_mocks()
    for url, body in ((SRC_URL, SRC), (MAN_URL, STD_MAN)):
        failing = (url == SRC_URL) == (bad == "artifact")
        direct_vm.mock_web("^" + url.replace(".", r"\.") + "$", {"method": "GET", "status": 404 if failing else 200, "body": body})
    with direct_vm.expect_revert("unreadable"):
        c.check(i)
    assert c.get_attestation(i)["checks"] == 0


def test_a_list_and_file_changed_together_are_still_drift(direct_vm, direct_deploy):
    """The publisher re-issuing a consistent list does not make the old attestation true again."""
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    i = _root(direct_vm, c)
    direct_vm.warp(T1)
    new = b"a whole new release"
    _std(direct_vm, src=new, man=_man((_d(new), "app-1.0.tar.gz")))
    c.check(i)
    a = c.get_attestation(i)
    assert a["status"] == "drifted" and a["digest"] == _d(SRC) and a["last_digest"] == _d(new)
    assert c.is_trusted(i, 0) is False


def test_an_unlisted_child_is_still_held_to_its_parent_when_rechecked(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    _std(direct_vm, man=_man((_d(SRC), "app-1.0.tar.gz")))  # the list does not name the binary yet
    c.check(child)
    assert c.get_attestation(child)["status"] == "unlisted"
    direct_vm.warp(T1)
    _std(direct_vm, src=b"silently replaced")
    c.check(root)
    assert c.get_attestation(root)["status"] == "drifted"
    direct_vm.warp(T2)
    _std(direct_vm)  # the publisher now lists the binary, but the parent is no longer verified
    with direct_vm.expect_revert("parent is not verified"):
        c.check(child)
    assert c.get_attestation(child)["status"] == "unlisted" and c.get_attestation(child)["digest"] == ""


def test_a_huge_line_cannot_be_used_to_vouch_for_the_parent(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    man = _man((_d(BIN), "app-linux-amd64")) + "\n" + _d(SRC) + "  " + "x" * 1100
    _std(direct_vm, man=man)
    c.check(child)
    assert c.get_attestation(child)["status"] == "unbound"


# ---------------------------------------------------------------------------
# publisher-pinned trust
# ---------------------------------------------------------------------------


def test_trace_reports_where_each_link_was_vouched_for(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    t = c.trace(child)
    assert [(n["artifact_url"], n["manifest_url"]) for n in t] == [(BIN_URL, MAN_URL), (SRC_URL, MAN_URL)]


def test_trust_from_a_publisher_requires_every_list_to_live_under_the_prefix(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    c.check(child)
    assert c.is_trusted_from(child, 0, "https://dl.example.com/") is True
    assert c.is_trusted_from(child, 0, "https://dl.example.com/SHA") is False  # a prefix must end in a slash
    assert c.is_trusted_from(root, 0, "https://dl.example.com/") is True
    assert c.is_trusted_from(child, 0, "https://other.example.org/") is False
    assert c.is_trusted_from(child, 0, "https://dl.example.com/releases/") is False


def test_one_foreign_link_in_the_chain_breaks_publisher_trust(direct_vm, direct_deploy):
    """An attacker who vouches for the child on their own site gets is_trusted, but not trust from the real publisher."""
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    evil = "https://evil.example.net/SHA256SUMS"
    _std(direct_vm)
    _serve(direct_vm, {SRC_URL: SRC, BIN_URL: BIN, MAN_URL: STD_MAN, evil: STD_MAN})
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root, manifest=evil)
    c.check(child)
    assert c.get_attestation(child)["status"] == "verified"
    assert c.is_trusted(child, 0) is True
    assert c.is_trusted_from(child, 0, "https://dl.example.com/") is False
    assert c.is_trusted_from(child, 0, "https://evil.example.net/") is False  # the root is not under it


def test_a_lookalike_host_does_not_satisfy_a_prefix(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    lookalike = "https://dl.example.com.evil.net/SHA256SUMS"
    _serve(direct_vm, {SRC_URL: SRC, lookalike: STD_MAN})
    root = _att(c, manifest=lookalike)
    c.check(root)
    assert c.is_trusted(root, 0) is True
    assert c.is_trusted_from(root, 0, "https://dl.example.com/") is False
    assert c.is_trusted_from(root, 0, "https://dl.example.com.evil.net/") is True


def test_publisher_trust_still_needs_verified_links_and_fresh_checks(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    child = _att(c, artifact=BIN_URL, name="app-linux-amd64", parent=root)
    assert c.is_trusted_from(child, 0, "https://dl.example.com/") is False  # pending
    c.check(child)
    direct_vm.warp(T3)
    assert c.is_trusted_from(child, 0, "https://dl.example.com/") is True
    assert c.is_trusted_from(child, 3600, "https://dl.example.com/") is False  # too old
    direct_vm.warp(T1)
    _std(direct_vm, src=b"upstream compromised")
    c.check(root)
    assert c.is_trusted_from(child, 0, "https://dl.example.com/") is False  # tainted


def test_publisher_trust_never_reverts_on_a_bad_prefix(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    _std(direct_vm)
    root = _root(direct_vm, c)
    assert c.is_trusted_from(root, 0, "https://dl.example.com/") is True
    for bad in ("", "http://dl.example.com/", "https://dl.example.com", "dl.example.com/", 5, None, "https://dl.example.com/" + "a" * 300 + "/"):
        assert c.is_trusted_from(root, 0, bad) is False
    assert c.is_trusted_from(root, -1, "https://dl.example.com/") is False
    assert c.is_trusted_from("unknown", 0, "https://dl.example.com/") is False
