-- Insecure seed configuration for the Shell-Escape puzzle game.
-- This is the "before" state that the hardening migration must fix in place.
PRAGMA foreign_keys = OFF;

CREATE TABLE rooms (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    hint        TEXT,
    is_locked   INTEGER NOT NULL
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

-- Rooms: every hint leaks the answer in plaintext, and everything ships unlocked.
INSERT INTO rooms (id, name, description, hint, is_locked) VALUES
 (1, 'Foyer',        'Entry room; chain basic tools to escape.', 'answer: echo hi | base64', 0),
 (2, 'Pipework',     'Reveal the code by piping commands.',       'run: cat flag | sha256sum', 0),
 (3, 'Sorting Hall', 'Order matters in here.',                    'sort then head -n1',        0),
 (4, 'Admin Vault',  'Should be locked to non-admins.',           'use: unlock *',             0),
 (5, 'Network Nook', 'A legacy challenge left the door open.',    'curl the local port',       0),
 (6, 'Archive',      'Old dusty room.',                           'perl one-liner does it',    0);

-- Allowed commands: a mix of vetted coreutils utilities, wildcard/admin
-- "unlock everything" entries, and unsafe non-coreutils / dangerous commands.
INSERT INTO allowed_commands (id, room_id, command) VALUES
 (1,  1, 'ls'),
 (2,  1, 'echo'),
 (3,  1, 'base64'),
 (4,  1, 'cat'),
 (5,  1, 'grep flag'),
 (6,  1, '*'),
 (7,  2, 'cat'),
 (8,  2, 'sha256sum'),
 (9,  2, 'sed -n 1p'),
 (10, 2, 'curl'),
 (11, 3, 'sort'),
 (12, 3, 'head'),
 (13, 3, 'tail'),
 (14, 3, 'uniq'),
 (15, 3, 'awk {print}'),
 (16, 4, 'unlock *'),
 (17, 4, 'sudo *'),
 (18, 4, 'admin'),
 (19, 4, 'chroot /'),
 (20, 5, 'nc -l'),
 (21, 5, 'wget'),
 (22, 5, 'python3'),
 (23, 5, 'env'),
 (24, 6, 'perl'),
 (25, 6, 'rm -rf /'),
 (26, 6, 'dd if=/dev/zero'),
 (27, 6, 'tr a-z A-Z'),
 (28, 6, 'wc -l');

-- Challenge checks: some point at safe vetted commands, others at commands that
-- are unsafe / wildcard / not part of the vetted toolset.
INSERT INTO challenge_checks (id, room_id, expected_command, points) VALUES
 (1,  1, 'base64',      10),
 (2,  1, 'grep flag',    5),
 (3,  2, 'sha256sum',   15),
 (4,  2, 'curl',        20),
 (5,  3, 'sort',        10),
 (6,  3, 'awk {print}', 10),
 (7,  4, 'unlock *',    50),
 (8,  5, 'env',         10),
 (9,  5, 'nc -l',       25),
 (10, 6, 'tr a-z A-Z',  10),
 (11, 6, 'perl',        30);
