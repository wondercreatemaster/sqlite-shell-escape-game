-- Insecure seed configuration for the Shell-Escape puzzle game.
-- This is the "before" state that the hardening migration must fix in place.
-- Command strings are adversarial: POSIX shell quoting AND backslash escaping
-- hide pipes, comments, and glob characters, so naive whitespace/`|`/`#`/`*`
-- handling gives wrong results. Commands must be canonicalized and parsed with a
-- correct quote- and escape-aware lexer. The challenge_checks.points values are
-- stale placeholders that must be recomputed.
PRAGMA foreign_keys = OFF;

CREATE TABLE rooms (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    hint        TEXT,
    is_locked   INTEGER NOT NULL,
    cmd_digest  TEXT NOT NULL
);

CREATE TABLE allowed_commands (
    id       INTEGER PRIMARY KEY,
    room_id  INTEGER NOT NULL,
    command  TEXT NOT NULL
);

CREATE TABLE challenge_checks (
    id               INTEGER PRIMARY KEY,
    room_id          INTEGER NOT NULL,
    expected_command TEXT NOT NULL,
    points           INTEGER NOT NULL
);

CREATE TABLE doors (
    id          INTEGER PRIMARY KEY,
    from_room   INTEGER NOT NULL,
    to_room     INTEGER NOT NULL,
    via_command TEXT NOT NULL
);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Rooms: hints leak answers, everything ships unlocked, cmd_digest is stale.
INSERT INTO rooms (id, name, description, hint, is_locked, cmd_digest) VALUES
 (1, 'Foyer',        'Entry room; chain basic tools to escape.', 'answer: echo hi | base64', 0, 'STALE'),
 (2, 'Pipework',     'Reveal the code by piping commands.',       'run: cat flag | sha256sum', 0, 'STALE'),
 (3, 'Sorting Hall', 'Order matters in here.',                    'sort then head -n1',        0, 'STALE'),
 (4, 'Admin Vault',  'Should be locked to non-admins.',           'use: unlock *',             0, 'STALE'),
 (5, 'Network Nook', 'A legacy challenge left the door open.',    'curl the local port',       0, 'STALE'),
 (6, 'Archive',      'Old dusty room.',                           'perl one-liner does it',    0, 'STALE');

-- Allowed commands: vetted coreutils utilities (quoted args, quoted/escaped
-- pipes and globs, inline comments, env wrappers, absolute paths) mixed with
-- wildcard/admin entries and unsafe/dangerous commands.
INSERT INTO allowed_commands (id, room_id, command) VALUES
 (1,  1, 'ls'),
 (2,  1, '  echo   hi  # greet '),
 (3,  1, 'echo ''a|b'''),
 (4,  1, 'echo ''*'''),
 (5,  1, 'echo \*'),
 (6,  1, 'echo a\ b'),
 (7,  1, 'ls *'),
 (8,  1, 'cat data | grep flag'),
 (9,  2, 'env   base64'),
 (10, 2, 'sha256sum "big file"'),
 (11, 2, 'sed -n 1p'),
 (12, 2, 'cat x | ''curl'' -'),
 (13, 3, '/usr/bin/head -n5 # top'),
 (14, 3, 'tr a\|b x'),
 (15, 3, 'tac file | tee out'),
 (16, 3, 'awk "{print $1}"'),
 (17, 4, 'unlock *'),
 (18, 4, 'sudo ''sh'''),
 (19, 4, 'admin'),
 (20, 4, 'FOO=1 rm -rf /'),
 (21, 5, 'nc -l 8080'),
 (22, 5, 'env python3 -m http'),
 (23, 5, 'wget'),
 (24, 5, 'env -i PATH=/bin   cat'),
 (25, 6, 'perl -e 1'),
 (26, 6, 'dd if=/dev/zero'),
 (27, 6, 'tr  ''a-z''   ''A-Z'''),
 (28, 6, 'wc -l | cat'),
 (29, 6, 'shred -u old');

-- Challenge checks: reference commands (also messy/quoted/escaped); points are
-- stale zeros to be recomputed for surviving rows.
INSERT INTO challenge_checks (id, room_id, expected_command, points) VALUES
 (1,  1, 'echo ''*''',            0),
 (2,  1, 'cat data | grep flag',  0),
 (3,  1, '  echo   hi   # greet', 0),
 (4,  1, 'echo \*',               0),
 (5,  2, 'env   base64',          0),
 (6,  2, 'sed -n 1p',             0),
 (7,  3, 'tac file | tee out',    0),
 (8,  3, 'awk "{print $1}"',      0),
 (9,  4, 'unlock *',              0),
 (10, 5, 'env -i PATH=/bin   cat', 0),
 (11, 5, 'nc -l 8080',            0),
 (12, 6, 'wc -l | cat',           0),
 (13, 6, 'perl -e 1',             0),
 (14, 6, 'tr  ''a-z'' ''A-Z''',   0);

-- Doors: directed edges gated by a command that must survive hardening in the
-- source room for the door to be usable.
INSERT INTO doors (id, from_room, to_room, via_command) VALUES
 (1, 1, 2, 'ls'),
 (2, 1, 3, 'echo ''*'''),
 (3, 2, 5, 'sha256sum "big file"'),
 (4, 2, 4, 'sed -n 1p'),
 (5, 3, 4, 'awk "{print $1}"'),
 (6, 3, 6, 'grep x'),
 (7, 5, 6, 'wget'),
 (8, 6, 1, 'tr  ''a-z'' ''A-Z''');

-- Meta: schema_version stays as-is; manifest is a stale placeholder.
INSERT INTO meta (key, value) VALUES
 ('schema_version', '1'),
 ('manifest',       'STALE');
