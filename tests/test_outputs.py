"""End-to-end verification for the Shell-Escape database hardening task.

The expected hardened state is recomputed from trusted inputs that the verifier
carries itself -- a pristine copy of the seed shipped alongside this file
(`tests/seed_reference.sql`) and the GNU coreutils 9.5 utility set embedded
below -- then compared against the agent's database at `/app/game/escape.db`.
The verifier deliberately does NOT read any agent-writable file (e.g.
`/opt/seed/seed.sql` or `/app/coreutils-9.5.tar.gz`) when deriving the expected
state, so an agent cannot move the goalposts by tampering with those inputs.
"""

import hashlib
import hmac
import os
import re
import sqlite3
from collections import deque
from pathlib import Path

DB_PATH = "/app/game/escape.db"
SEED_PATH = str(Path(__file__).resolve().parent / "seed_reference.sql")

DENYLIST = {"rm", "dd", "shred", "chroot", "runcon"}
HMAC_KEY = b"shell-escape"
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

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
    """Canonical form: strip inline comment, collapse whitespace runs, trim."""
    command = command.split("#", 1)[0]
    return re.sub(r"\s+", " ", command).strip()


def _stage_program(stage: str):
    """Program of one pipeline stage, or None if the stage names no program."""
    tokens = stage.split()
    i = 0
    while i < len(tokens) and ASSIGN.match(tokens[i]):
        i += 1
    if i >= len(tokens):
        return None
    prog = os.path.basename(tokens[i])
    if prog == "env":
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or ASSIGN.match(tokens[i])):
            i += 1
        if i >= len(tokens):
            return "env"
        prog = os.path.basename(tokens[i])
    return prog


def _programs(command: str):
    """All programs a (canonical) command runs, one per `|`-separated stage."""
    return [_stage_program(stage) for stage in command.split("|")]


def _is_safe(command: str, approved: set) -> bool:
    """A canonical command is safe iff every stage program is vetted, no glob."""
    if "*" in command or "?" in command:
        return False
    for prog in _programs(command):
        if prog is None or prog not in approved or prog in DENYLIST:
            return False
    return True


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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

    # Rule 5: delete non-usable doors.
    cur.execute(
        "DELETE FROM doors WHERE NOT EXISTS ("
        "SELECT 1 FROM allowed_commands a "
        "WHERE a.room_id = doors.from_room AND a.command = doors.via_command)"
    )

    # Rule 6: reachability from room 1 over surviving doors.
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

    # Rule 7: per-room cmd_digest.
    digests = {}
    for room_id in room_ids:
        cmds = [
            c
            for (c,) in cur.execute(
                "SELECT command FROM allowed_commands WHERE room_id = ?", (room_id,)
            ).fetchall()
        ]
        digest = _sha256_hex("\n".join(sorted(cmds)))
        digests[room_id] = digest
        cur.execute("UPDATE rooms SET cmd_digest = ? WHERE id = ?", (digest, room_id))

    # Rule 8: signed manifest.
    message = "\n".join(f"{room_id}={digests[room_id]}" for room_id in room_ids)
    manifest = hmac.new(HMAC_KEY, message.encode("utf-8"), hashlib.sha256).hexdigest()
    cur.execute("UPDATE meta SET value = ? WHERE key = 'manifest'", (manifest,))

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
        "SELECT room_id, command FROM allowed_commands ORDER BY room_id, command"
    ):
        parts.append("A|" + "|".join(str(x) for x in row))
    for row in cur.execute(
        "SELECT room_id, expected_command, points FROM challenge_checks "
        "ORDER BY room_id, expected_command, points"
    ):
        parts.append("C|" + "|".join(str(x) for x in row))
    for row in cur.execute(
        "SELECT from_room, to_room, via_command FROM doors "
        "ORDER BY from_room, to_room, via_command"
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
    """Rule 5: every surviving door's via_command survives in its from_room."""
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
    """Rule 6: is_locked=0 iff the room is reachable from room 1 via surviving doors."""
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
                f"Room {room_id} is_locked={locked}, expected {expected} "
                f"(reachable={sorted(reachable)})"
            )
    finally:
        con.close()


def test_cmd_digests_recomputed():
    """Rule 7: each room's cmd_digest is SHA-256 of its sorted surviving commands."""
    con = _open_agent_db()
    try:
        for room_id, in con.execute("SELECT id FROM rooms ORDER BY id"):
            cmds = [
                c
                for (c,) in con.execute(
                    "SELECT command FROM allowed_commands WHERE room_id = ?", (room_id,)
                ).fetchall()
            ]
            expected = _sha256_hex("\n".join(sorted(cmds)))
            (actual,) = con.execute(
                "SELECT cmd_digest FROM rooms WHERE id = ?", (room_id,)
            ).fetchone()
            assert actual == expected, (
                f"Room {room_id} cmd_digest mismatch: expected {expected}, got {actual}"
            )
    finally:
        con.close()


def test_manifest_hmac():
    """Rule 8: meta.manifest is the HMAC-SHA256 over the per-room digest lines."""
    con = _open_agent_db()
    try:
        rows = con.execute("SELECT id, cmd_digest FROM rooms ORDER BY id").fetchall()
        message = "\n".join(f"{room_id}={digest}" for room_id, digest in rows)
        expected = hmac.new(HMAC_KEY, message.encode("utf-8"), hashlib.sha256).hexdigest()
        (actual,) = con.execute(
            "SELECT value FROM meta WHERE key = 'manifest'"
        ).fetchone()
        assert actual == expected, (
            f"manifest mismatch: expected {expected}, got {actual}"
        )
    finally:
        con.close()


def test_canonical_state_matches_expected():
    """The agent DB's canonical checksum equals the independently recomputed one."""
    reference = _build_reference()
    con = _open_agent_db()
    try:
        expected = _checksum(reference)
        actual = _checksum(con)
        assert actual == expected, (
            "Canonical hardened state mismatch.\n"
            f"expected checksum: {expected}\n"
            f"actual checksum:   {actual}\n\n"
            f"expected:\n{_canonical(reference)}\n\n"
            f"actual:\n{_canonical(con)}"
        )
    finally:
        con.close()
        reference.close()
