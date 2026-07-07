-- Insecure seed configuration for the Shell-Escape puzzle game.
-- This is the "before" state that the hardening migration must fix in place.
-- Command strings are intentionally adversarial: shell quoting hides pipes,
-- comments, and glob characters, so naive whitespace/`|`/`#`/`*` handling gives
-- wrong results. Commands must be canonicalized and parsed quote-aware.
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

-- Allowed commands: vetted coreutils utilities (quoted args, quoted pipes/globs,
-- inline comments, env wrappers, absolute paths) mixed with wildcard/admin
-- entries and unsafe/dangerous commands.
INSERT INTO allowed_commands (id, room_id, command) VALUES
 (1,  1, 'ls'),
 (2,  1, '  echo   hi  # greet '),
 (3,  1, 'echo ''a|b'''),
 (4,  1, 'echo ''*'''),
 (5,  1, 'ls *'),
 (6,  1, 'cat data | grep flag'),
 (7,  2, 'env   base64'),
 (8,  2, 'sha256sum "big file"'),
 (9,  2, 'sed -n 1p'),
 (10, 2, 'cat x | ''curl'' -'),
 (11, 3, '/usr/bin/head -n5 # top'),
 (12, 3, 'tr ''a|b'' x'),
 (13, 3, 'tac file | tee out'),
 (14, 3, 'awk "{print $1}"'),
 (15, 4, 'unlock *'),
 (16, 4, 'sudo ''sh'''),
 (17, 4, 'admin'),
 (18, 4, 'FOO=1 rm -rf /'),
 (19, 5, 'nc -l 8080'),
 (20, 5, 'env python3 -m http'),
 (21, 5, 'wget'),
 (22, 5, 'env -i PATH=/bin   cat'),
 (23, 6, 'perl -e 1'),
 (24, 6, 'dd if=/dev/zero'),
 (25, 6, 'tr  ''a-z''   ''A-Z'''),
 (26, 6, 'wc -l | cat'),
 (27, 6, 'shred -u old');

-- Challenge checks reference commands that may be safe or unsafe once
-- canonicalized; expected_command strings are also messy/quoted.
INSERT INTO challenge_checks (id, room_id, expected_command, points) VALUES
 (1,  1, 'echo ''*''',           10),
 (2,  1, 'cat data | grep flag',  5),
 (3,  1, '  echo   hi   # greet', 7),
 (4,  2, 'env   base64',         15),
 (5,  2, 'sed -n 1p',            20),
 (6,  3, 'tac file | tee out',   12),
 (7,  3, 'awk "{print $1}"',      9),
 (8,  4, 'unlock *',             50),
 (9,  5, 'env -i PATH=/bin   cat', 8),
 (10, 5, 'nc -l 8080',           25),
 (11, 6, 'wc -l | cat',          11),
 (12, 6, 'perl -e 1',            30);

-- Doors: directed edges, each gated by a command that must survive hardening in
-- the source room for the door to be usable.
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
