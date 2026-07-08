"""End-to-end verification for the Shell-Escape database hardening task.

The expected hardened state is recomputed from trusted inputs that the verifier
carries itself -- a pristine copy of the seed shipped alongside this file
(`tests/seed_reference.sql`) and the GNU coreutils 9.5 utility set embedded
below -- then compared against the agent's database at `/app/game/escape.db`.
The verifier deliberately does NOT read any agent-writable file (e.g.
`/opt/seed/seed.sql` or `/app/coreutils-9.5.tar.gz`) when deriving the expected
state, so an agent cannot move the goalposts by tampering with those inputs.
"""

import base64
import hashlib
import hmac
import os
import re
import sqlite3
import struct
import zlib
from collections import deque
from pathlib import Path

DB_PATH = "/app/game/escape.db"
SEED_PATH = str(Path(__file__).resolve().parent / "seed_reference.sql")
# Trusted copy of the binary policy the verifier carries (never the agent's copy
# at /app/game/policy.bin), so the derived key/denylist cannot be tampered with.
POLICY_PATH = str(Path(__file__).resolve().parent / "policy.bin")

BASE_DENYLIST = {"rm", "dd", "shred", "chroot", "runcon"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _parse_policy(path: str):
    """Parse the big-endian policy v2 blob -> (rounds, hmac_key_bytes, extra_deny)."""
    blob = Path(path).read_bytes()
    assert blob[0:4] == b"SESC", "bad policy magic"
    assert blob[4] == 2, "bad policy version"
    off = 5
    (rounds,) = struct.unpack_from(">H", blob, off)
    off += 2
    (key_len,) = struct.unpack_from(">H", blob, off)
    off += 2
    key = blob[off:off + key_len]
    off += key_len
    (count,) = struct.unpack_from(">H", blob, off)
    off += 2
    extra = set()
    for _ in range(count):
        nlen = blob[off]
        off += 1
        extra.add(blob[off:off + nlen].decode("ascii"))
        off += nlen
    (crc,) = struct.unpack_from(">I", blob, off)
    assert zlib.crc32(blob[: len(blob) - 4]) & 0xFFFFFFFF == crc, "policy CRC mismatch"
    return rounds, key, extra


DIGEST_ROUNDS, HMAC_KEY, _EXTRA_DENY = _parse_policy(POLICY_PATH)
DENYLIST = BASE_DENYLIST | _EXTRA_DENY

# The programs shipped by GNU coreutils 9.5 (the trusted allowlist). This is the
# same set the agent is expected to extract from the staged tarball's README; we
# embed it here so the verifier's reference does not depend on any file the agent
# could modify during the task.
COREUTILS_9_5 = frozenset(
    """
    arch base32 base64 basename basenc cat chcon chgrp chmod chown chroot cksum
    comm cp csplit cut date dd df dir dircolors dirname du echo env expand expr
    factor false fmt fold groups head hostid id install join kill link ln logname
    ls md5sum mkdir mkfifo mknod mktemp mv nice nl nohup nproc numfmt od paste
    pathchk pinky pr printenv printf ptx pwd readlink realpath rm rmdir runcon seq
    sha1sum sha224sum sha256sum sha384sum sha512sum shred shuf sleep sort split
    stat stdbuf stty sum sync tac tail tee test timeout touch tr true truncate
    tsort tty uname unexpand uniq unlink uptime users vdir wc who whoami yes
    """.split()
)


def _canon(command: str) -> str:
    """Canonical form (quote/escape-aware): strip an unquoted, unescaped inline
    comment, collapse runs of unquoted, unescaped whitespace to one space, and
    trim such ends. Quotes, escape backslashes, and protected bytes are kept."""
    res = []
    i = 0
    n = len(command)
    in_single = in_double = False
    pending_space = False
    at_boundary = True  # start-of-string or after unquoted whitespace

    def flush():
        nonlocal pending_space
        if pending_space and res:
            res.append(" ")
        pending_space = False

    while i < n:
        ch = command[i]
        if in_single:
            res.append(ch)
            if ch == "'":
                in_single = False
            at_boundary = False
            i += 1
            continue
        if in_double:
            res.append(ch)
            if ch == '"':
                in_double = False
            at_boundary = False
            i += 1
            continue
        if ch == "\\":
            flush()
            if i + 1 < n:
                res.append("\\")
                res.append(command[i + 1])
                i += 2
            else:
                res.append("\\")
                i += 1
            at_boundary = False
            continue
        if ch == "'":
            flush()
            in_single = True
            res.append(ch)
            at_boundary = False
            i += 1
            continue
        if ch == '"':
            flush()
            in_double = True
            res.append(ch)
            at_boundary = False
            i += 1
            continue
        if ch.isspace():
            pending_space = True
            at_boundary = True
            i += 1
            continue
        if ch == "#" and at_boundary:
            break
        flush()
        res.append(ch)
        at_boundary = False
        i += 1
    return "".join(res)


def _scan_split(s: str, is_sep):
    """Split s on unquoted, unescaped separator chars (quote/escape-aware)."""
    parts = []
    cur = []
    i = 0
    n = len(s)
    in_single = in_double = False
    while i < n:
        ch = s[i]
        if in_single:
            cur.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            cur.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            if i + 1 < n:
                cur.append("\\")
                cur.append(s[i + 1])
                i += 2
            else:
                cur.append("\\")
                i += 1
            continue
        if ch == "'":
            in_single = True
            cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            cur.append(ch)
            i += 1
            continue
        if is_sep(ch):
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _unquote(token: str) -> str:
    """Literal value of a token: strip surrounding quotes and resolve escapes."""
    out = []
    i = 0
    n = len(token)
    in_single = in_double = False
    while i < n:
        ch = token[i]
        if in_single:
            if ch == "'":
                in_single = False
            else:
                out.append(ch)
            i += 1
            continue
        if in_double:
            if ch == '"':
                in_double = False
            else:
                out.append(ch)
            i += 1
            continue
        if ch == "\\":
            if i + 1 < n:
                out.append(token[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _has_glob(command: str) -> bool:
    """True iff the command has an unquoted, unescaped `*` or `?`."""
    i = 0
    n = len(command)
    in_single = in_double = False
    while i < n:
        ch = command[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "\\":
            i += 2 if i + 1 < n else 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch in "*?":
            return True
        i += 1
    return False


def _stages(command: str):
    """Pipeline stages of a canonical command (split on unquoted, unescaped `|`)."""
    return _scan_split(command, lambda c: c == "|")


def _stage_program(stage: str):
    """Program of one pipeline stage, or None if the stage names no program."""
    values = [_unquote(t) for t in _scan_split(stage, str.isspace) if t != ""]
    i = 0
    while i < len(values) and ASSIGN.match(values[i]):
        i += 1
    if i >= len(values):
        return None
    prog = os.path.basename(values[i])
    if prog == "env":
        i += 1
        while i < len(values) and (values[i].startswith("-") or ASSIGN.match(values[i])):
            i += 1
        if i >= len(values):
            return "env"
        prog = os.path.basename(values[i])
    return prog


def _programs(command: str):
    """All programs a (canonical) command runs, one per pipeline stage."""
    return [_stage_program(stage) for stage in _stages(command)]


def _points(command: str) -> int:
    """Recomputed challenge points: 7 * (#stages) + character length."""
    return 7 * len(_stages(command)) + len(command)


def _is_safe(command: str, approved: set) -> bool:
    """A canonical command is safe iff it has no unquoted glob and every stage
    program is a vetted, non-denylisted coreutils utility."""
    if _has_glob(command):
        return False
    for prog in _programs(command):
        if prog is None or prog not in approved or prog in DENYLIST:
            return False
    return True


def _digest(text: str) -> str:
    """R-times-iterated SHA-256 (raw-byte chaining), lowercase hex of final digest."""
    h = text.encode("utf-8")
    for _ in range(DIGEST_ROUNDS):
        h = hashlib.sha256(h).digest()
    return h.hex()


def _manifest(message: str) -> str:
    """RFC 4648 Base32 (uppercase, padded) of the raw HMAC-SHA256 digest bytes."""
    raw = hmac.new(HMAC_KEY, message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b32encode(raw).decode("ascii")


def _build_reference() -> sqlite3.Connection:
    """Recreate the seed DB in memory and apply the eight hardening rules to it."""
    approved = COREUTILS_9_5
    con = sqlite3.connect(":memory:")
    con.executescript(Path(SEED_PATH).read_text())
    cur = con.cursor()

    # Rule 1: canonicalize command columns.
    for table, col in (
        ("allowed_commands", "command"),
        ("challenge_checks", "expected_command"),
        ("doors", "via_command"),
    ):
        for row_id, value in cur.execute(f"SELECT id, {col} FROM {table}").fetchall():
            cur.execute(
                f"UPDATE {table} SET {col} = ? WHERE id = ?", (_canon(value), row_id)
            )

    # Rule 2: wipe hints.
    cur.execute("UPDATE rooms SET hint = NULL")

    # Rule 3: whitelist allowed_commands.
    for row_id, command in cur.execute("SELECT id, command FROM allowed_commands").fetchall():
        if not _is_safe(command, approved):
            cur.execute("DELETE FROM allowed_commands WHERE id = ?", (row_id,))

    # Rule 4: prune orphan challenge_checks.
    cur.execute(
        "DELETE FROM challenge_checks WHERE NOT EXISTS ("
        "SELECT 1 FROM allowed_commands a "
        "WHERE a.room_id = challenge_checks.room_id "
        "AND a.command = challenge_checks.expected_command)"
    )

    # Rule 5: recompute points for surviving challenge_checks.
    for row_id, expected in cur.execute(
        "SELECT id, expected_command FROM challenge_checks"
    ).fetchall():
        cur.execute(
            "UPDATE challenge_checks SET points = ? WHERE id = ?",
            (_points(expected), row_id),
        )

    # Rule 6: delete non-usable doors.
    cur.execute(
        "DELETE FROM doors WHERE NOT EXISTS ("
        "SELECT 1 FROM allowed_commands a "
        "WHERE a.room_id = doors.from_room AND a.command = doors.via_command)"
    )

    # Rule 7: reachability from room 1 over surviving doors.
    adj = {}
    for f, t in cur.execute("SELECT from_room, to_room FROM doors").fetchall():
        adj.setdefault(f, []).append(t)
    reachable = {1}
    queue = deque([1])
    while queue:
        u = queue.popleft()
        for v in adj.get(u, []):
            if v not in reachable:
                reachable.add(v)
                queue.append(v)
    room_ids = [r for (r,) in cur.execute("SELECT id FROM rooms ORDER BY id").fetchall()]
    for room_id in room_ids:
        cur.execute(
            "UPDATE rooms SET is_locked = ? WHERE id = ?",
            (0 if room_id in reachable else 1, room_id),
        )

    # Rule 8: per-room cmd_digest.
    digests = {}
    for room_id in room_ids:
        cmds = [
            c
            for (c,) in cur.execute(
                "SELECT command FROM allowed_commands WHERE room_id = ?", (room_id,)
            ).fetchall()
        ]
        digest = _digest("\n".join(sorted(cmds)))
        digests[room_id] = digest
        cur.execute("UPDATE rooms SET cmd_digest = ? WHERE id = ?", (digest, room_id))

    # Rule 9: signed manifest (Base32 of raw HMAC bytes).
    message = "\n".join(f"{room_id}={digests[room_id]}" for room_id in room_ids)
    cur.execute("UPDATE meta SET value = ? WHERE key = 'manifest'", (_manifest(message),))

    con.commit()
    return con


def _canonical(con: sqlite3.Connection) -> str:
    """Order-independent canonical dump of all five tables (see instruction.md)."""
    cur = con.cursor()
    parts = []
    for row in cur.execute(
        "SELECT id, name, description, COALESCE(hint, ''), is_locked, cmd_digest "
        "FROM rooms ORDER BY id"
    ):
        parts.append("R|" + "|".join(str(x) for x in row))
    for row in cur.execute(
        "SELECT id, room_id, command FROM allowed_commands ORDER BY id"
    ):
        parts.append("A|" + "|".join(str(x) for x in row))
    for row in cur.execute(
        "SELECT id, room_id, expected_command, points FROM challenge_checks ORDER BY id"
    ):
        parts.append("C|" + "|".join(str(x) for x in row))
    for row in cur.execute(
        "SELECT id, from_room, to_room, via_command FROM doors ORDER BY id"
    ):
        parts.append("D|" + "|".join(str(x) for x in row))
    for row in cur.execute("SELECT key, value FROM meta ORDER BY key"):
        parts.append("M|" + "|".join(str(x) for x in row))
    return "\n".join(parts)


def _checksum(con: sqlite3.Connection) -> str:
    return hashlib.sha256(_canonical(con).encode()).hexdigest()


def _open_agent_db() -> sqlite3.Connection:
    """Open the agent's database read-only so tests never mutate it."""
    assert Path(DB_PATH).exists(), f"Database {DB_PATH} does not exist"
    return sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)


def test_database_exists():
    """The hardened SQLite database is present at /app/game/escape.db."""
    assert Path(DB_PATH).exists(), f"Database {DB_PATH} does not exist"


def test_schema_unchanged():
    """All five tables still exist with their original columns."""
    con = _open_agent_db()
    try:
        expected = {
            "rooms": ["id", "name", "description", "hint", "is_locked", "cmd_digest"],
            "allowed_commands": ["id", "room_id", "command"],
            "challenge_checks": ["id", "room_id", "expected_command", "points"],
            "doors": ["id", "from_room", "to_room", "via_command"],
            "meta": ["key", "value"],
        }
        for table, cols in expected.items():
            info = con.execute(f"PRAGMA table_info({table})").fetchall()
            assert info, f"Table {table} is missing"
            assert [c[1] for c in info] == cols, f"Schema of {table} was altered"
    finally:
        con.close()


def test_commands_are_canonical():
    """Rule 1: stored command strings are in canonical form."""
    con = _open_agent_db()
    try:
        for command, in con.execute("SELECT command FROM allowed_commands"):
            assert command == _canon(command), f"Non-canonical command: {command!r}"
        for command, in con.execute("SELECT expected_command FROM challenge_checks"):
            assert command == _canon(command), f"Non-canonical expected_command: {command!r}"
        for command, in con.execute("SELECT via_command FROM doors"):
            assert command == _canon(command), f"Non-canonical via_command: {command!r}"
    finally:
        con.close()


def test_no_plaintext_hints():
    """Rule 2: every room hint has been wiped to NULL."""
    con = _open_agent_db()
    try:
        leaked = con.execute("SELECT id FROM rooms WHERE hint IS NOT NULL").fetchall()
        assert not leaked, f"Rooms still carry plaintext hints: {leaked}"
    finally:
        con.close()


def test_allowed_commands_are_whitelisted():
    """Rule 3: every surviving command is safe (all stage programs vetted, no glob)."""
    approved = COREUTILS_9_5
    con = _open_agent_db()
    try:
        for command, in con.execute("SELECT command FROM allowed_commands"):
            assert _is_safe(command, approved), (
                f"Unsafe command survived: {command!r} (programs: {_programs(command)})"
            )
    finally:
        con.close()


def test_no_orphan_challenges():
    """Rule 4: every challenge references a surviving command in the same room."""
    con = _open_agent_db()
    try:
        orphans = con.execute(
            "SELECT c.room_id, c.expected_command FROM challenge_checks c "
            "WHERE NOT EXISTS (SELECT 1 FROM allowed_commands a "
            "WHERE a.room_id = c.room_id AND a.command = c.expected_command)"
        ).fetchall()
        assert not orphans, f"Orphan challenge_checks rows remain: {orphans}"
    finally:
        con.close()


def test_doors_are_usable():
    """Rule 6: every surviving door's via_command survives in its from_room."""
    con = _open_agent_db()
    try:
        bad = con.execute(
            "SELECT d.from_room, d.to_room, d.via_command FROM doors d "
            "WHERE NOT EXISTS (SELECT 1 FROM allowed_commands a "
            "WHERE a.room_id = d.from_room AND a.command = d.via_command)"
        ).fetchall()
        assert not bad, f"Non-usable doors remain: {bad}"
    finally:
        con.close()


def test_reachability_lock_state():
    """Rule 7: is_locked=0 iff the room is reachable from room 1 via surviving doors."""
    con = _open_agent_db()
    try:
        adj = {}
        for f, t in con.execute("SELECT from_room, to_room FROM doors"):
            adj.setdefault(f, []).append(t)
        reachable = {1}
        queue = deque([1])
        while queue:
            u = queue.popleft()
            for v in adj.get(u, []):
                if v not in reachable:
                    reachable.add(v)
                    queue.append(v)
        for room_id, locked in con.execute("SELECT id, is_locked FROM rooms ORDER BY id"):
            expected = 0 if room_id in reachable else 1
            assert locked == expected, (
                f"Room {room_id} has the wrong is_locked value ({locked})"
            )
    finally:
        con.close()


def test_cmd_digests_recomputed():
    """Rule 8: each room's cmd_digest is the R-round iterated SHA-256 of its commands."""
    con = _open_agent_db()
    try:
        for room_id, in con.execute("SELECT id FROM rooms ORDER BY id"):
            cmds = [
                c
                for (c,) in con.execute(
                    "SELECT command FROM allowed_commands WHERE room_id = ?", (room_id,)
                ).fetchall()
            ]
            expected = _digest("\n".join(sorted(cmds)))
            (actual,) = con.execute(
                "SELECT cmd_digest FROM rooms WHERE id = ?", (room_id,)
            ).fetchone()
            assert actual == expected, (
                f"Room {room_id} cmd_digest is incorrect (got {actual})"
            )
    finally:
        con.close()


def test_manifest_hmac():
    """Rule 9: meta.manifest is the Base32 of the HMAC-SHA256 over per-room digest lines."""
    con = _open_agent_db()
    try:
        rows = con.execute("SELECT id, cmd_digest FROM rooms ORDER BY id").fetchall()
        message = "\n".join(f"{room_id}={digest}" for room_id, digest in rows)
        expected = _manifest(message)
        (actual,) = con.execute(
            "SELECT value FROM meta WHERE key = 'manifest'"
        ).fetchone()
        assert actual == expected, f"manifest is incorrect (got {actual})"
    finally:
        con.close()


def test_points_recomputed():
    """Rule 5: each surviving challenge's points == 7*stages + canonical length."""
    con = _open_agent_db()
    try:
        for room_id, expected_command, points in con.execute(
            "SELECT room_id, expected_command, points FROM challenge_checks"
        ):
            assert points == _points(expected_command), (
                f"Room {room_id} challenge {expected_command!r} has wrong points ({points})"
            )
    finally:
        con.close()


def test_lexer_edge_cases():
    """Quote/escape traps: quoted or escaped globs/pipes/spaces are literal and
    their commands survive, while unquoted globs and bad pipelines are removed."""
    con = _open_agent_db()
    try:
        commands = {c for (c,) in con.execute("SELECT command FROM allowed_commands")}
        must_keep = [
            "echo '*'",      # quoted glob -> literal
            "echo \\*",      # escaped glob -> literal
            "echo 'a|b'",    # quoted pipe -> single stage
            "echo a\\ b",    # escaped space -> single argument
        ]
        for cmd in must_keep:
            assert cmd in commands, f"safe command should survive: {cmd!r}"
        must_drop = [
            "ls *",                  # unquoted glob
            "cat data | grep flag",  # non-coreutils stage
            "tr a\\|b x",            # program tr is denylisted by the policy blob
            "tac file | tee out",    # program tee is denylisted by the policy blob
        ]
        for cmd in must_drop:
            assert cmd not in commands, f"unsafe command should be removed: {cmd!r}"
    finally:
        con.close()


def test_untouched_data_preserved():
    """Columns/rows not mentioned by the rules are left exactly as seeded."""
    seed = sqlite3.connect(":memory:")
    seed.executescript(Path(SEED_PATH).read_text())
    con = _open_agent_db()
    try:
        expected = seed.execute(
            "SELECT id, name, description FROM rooms ORDER BY id"
        ).fetchall()
        actual = con.execute(
            "SELECT id, name, description FROM rooms ORDER BY id"
        ).fetchall()
        assert actual == expected, "room name/description columns were modified"
        (schema_version,) = con.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        assert schema_version == "1", "meta.schema_version was modified"
    finally:
        con.close()
        seed.close()


def test_no_extra_or_missing_rows():
    """Every table's row count matches the independently recomputed reference."""
    reference = _build_reference()
    con = _open_agent_db()
    try:
        for table in ("rooms", "allowed_commands", "challenge_checks", "doors", "meta"):
            expected = reference.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            actual = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            # Do not print the expected count (it reveals how many rows survive).
            assert actual == expected, f"{table} has an unexpected row count ({actual})"
    finally:
        con.close()
        reference.close()


def test_row_ids_preserved():
    """Rows are not renumbered: surviving rows keep their original seed ids."""
    reference = _build_reference()
    con = _open_agent_db()
    try:
        for table in ("allowed_commands", "challenge_checks", "doors"):
            expected_ids = sorted(
                r[0] for r in reference.execute(f"SELECT id FROM {table}")
            )
            actual_ids = sorted(r[0] for r in con.execute(f"SELECT id FROM {table}"))
            # Do not print the expected id set (it reveals which rows survive).
            assert actual_ids == expected_ids, (
                f"{table} ids do not match the expected set (got {actual_ids})"
            )
    finally:
        con.close()
        reference.close()


def test_canonical_state_matches_expected():
    """The agent DB's canonical checksum equals the independently recomputed one."""
    reference = _build_reference()
    con = _open_agent_db()
    try:
        expected = _checksum(reference)
        actual = _checksum(con)
        # NOTE: deliberately do NOT emit the expected reference state or checksum
        # here -- run logs (e.g. harbor's jobs/) capture verifier stdout, and
        # leaking the target would let an agent copy it instead of solving. Report
        # only the agent's own state to aid debugging without revealing the answer.
        assert actual == expected, (
            "Canonical hardened state does not match the expected reference.\n"
            f"actual (agent) canonical state:\n{_canonical(con)}"
        )
    finally:
        con.close()
        reference.close()
