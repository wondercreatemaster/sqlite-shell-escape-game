"""End-to-end verification for the Shell-Escape database hardening task.

The expected hardened state is recomputed independently from the pristine seed
(`/opt/seed/seed.sql`) and the staged coreutils tarball
(`/app/coreutils-9.5.tar.gz`), then compared against the agent's database at
`/app/game/escape.db`. Nothing is hard-coded, so the tests stay correct for the
exact coreutils release that is actually staged in the image.
"""

import hashlib
import os
import sqlite3
import tarfile
from pathlib import Path

DB_PATH = "/app/game/escape.db"
SEED_PATH = "/opt/seed/seed.sql"
TARBALL_PATH = "/app/coreutils-9.5.tar.gz"

DENYLIST = {"rm", "dd", "shred", "chroot", "runcon"}


def _program(command: str) -> str:
    """Program of a command: basename of its first whitespace-separated token."""
    tokens = command.strip().split()
    if not tokens:
        return ""
    return os.path.basename(tokens[0])


def _coreutils_utilities() -> set:
    """Parse the vetted utility names from the coreutils tarball's top-level README."""
    with tarfile.open(TARBALL_PATH, "r:gz") as tf:
        member = None
        for m in tf.getmembers():
            if m.name.endswith("/README") and m.name.count("/") == 1:
                member = m
                break
        assert member is not None, "README not found in coreutils tarball"
        text = tf.extractfile(member).read().decode("utf-8", "replace")

    grab = False
    started = False
    tokens = []
    for line in text.splitlines():
        if not grab:
            if "programs that can be built" in line:
                grab = True
            continue
        if line.strip() == "":
            if started:
                break
            continue
        started = True
        tokens.extend(line.replace("[", "").replace("]", "").split())
    return set(tokens)


def _build_reference() -> sqlite3.Connection:
    """Recreate the seed DB in memory and apply the four hardening rules to it."""
    approved = _coreutils_utilities()
    con = sqlite3.connect(":memory:")
    con.executescript(Path(SEED_PATH).read_text())
    cur = con.cursor()

    # Rule 1 & 2
    cur.execute("UPDATE rooms SET hint = NULL")
    cur.execute("UPDATE rooms SET is_locked = CASE WHEN id = 1 THEN 0 ELSE 1 END")

    # Rule 3
    for row_id, command in cur.execute(
        "SELECT id, command FROM allowed_commands"
    ).fetchall():
        wildcard = "*" in command or "?" in command
        prog = _program(command)
        keep = (not wildcard) and (prog in approved) and (prog not in DENYLIST)
        if not keep:
            cur.execute("DELETE FROM allowed_commands WHERE id = ?", (row_id,))

    # Rule 4
    cur.execute(
        "DELETE FROM challenge_checks WHERE NOT EXISTS ("
        "SELECT 1 FROM allowed_commands a "
        "WHERE a.room_id = challenge_checks.room_id "
        "AND a.command = challenge_checks.expected_command)"
    )
    con.commit()
    return con


def _canonical(con: sqlite3.Connection) -> str:
    """Order-independent canonical dump of the three tables (see instruction.md)."""
    cur = con.cursor()
    parts = []
    for row in cur.execute(
        "SELECT id, name, description, COALESCE(hint, ''), is_locked "
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
    """The three original tables still exist with their original columns."""
    con = _open_agent_db()
    try:
        expected = {
            "rooms": ["id", "name", "description", "hint", "is_locked"],
            "allowed_commands": ["id", "room_id", "command"],
            "challenge_checks": ["id", "room_id", "expected_command", "points"],
        }
        for table, cols in expected.items():
            info = con.execute(f"PRAGMA table_info({table})").fetchall()
            assert info, f"Table {table} is missing"
            assert [c[1] for c in info] == cols, f"Schema of {table} was altered"
    finally:
        con.close()


def test_no_plaintext_hints():
    """Rule 1: every room hint has been wiped to NULL."""
    con = _open_agent_db()
    try:
        leaked = con.execute(
            "SELECT id FROM rooms WHERE hint IS NOT NULL"
        ).fetchall()
        assert not leaked, f"Rooms still carry plaintext hints: {leaked}"
    finally:
        con.close()


def test_room_lock_state():
    """Rule 2: only the entry room (id=1) is unlocked; all others are locked."""
    con = _open_agent_db()
    try:
        rows = con.execute("SELECT id, is_locked FROM rooms ORDER BY id").fetchall()
        for room_id, locked in rows:
            expected = 0 if room_id == 1 else 1
            assert locked == expected, (
                f"Room {room_id} has is_locked={locked}, expected {expected}"
            )
    finally:
        con.close()


def test_allowed_commands_are_whitelisted():
    """Rule 3: surviving commands are non-wildcard, vetted, non-denylisted coreutils."""
    approved = _coreutils_utilities()
    con = _open_agent_db()
    try:
        rows = con.execute("SELECT command FROM allowed_commands").fetchall()
        for (command,) in rows:
            assert "*" not in command and "?" not in command, (
                f"Wildcard command survived: {command!r}"
            )
            prog = _program(command)
            assert prog in approved, f"Non-coreutils command survived: {command!r}"
            assert prog not in DENYLIST, f"Denylisted command survived: {command!r}"
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
