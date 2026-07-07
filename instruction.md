We ship a tiny "shell-escape" puzzle game backed by a SQLite database at `/app/game/escape.db`, and the seeded config in there right now is a security mess: room hints leak the answers in plaintext, every room is unlocked, the `rooms.cmd_digest` integrity column is stale, there are wildcard / `admin` "unlock everything" entries, and several challenges point at unsafe commands that aren't part of our vetted toolset. Harden this database in place.

The only commands we trust are the standard GNU coreutils utilities. The coreutils 9.5 source tarball is staged at `/app/coreutils-9.5.tar.gz` (there's no network access) and the canonical list of utility names is in its top-level `README`. First, figure out the set of **programs** a command actually runs: split the command on `|` into pipeline stages; within each stage drop any leading `VAR=value` environment assignments, and if the first remaining token's basename is `env`, drop that `env` plus any following `-option` or `VAR=value` tokens; the stage's program is the basename (path stripped) of the next token. A command may run several programs (one per stage).

Now apply exactly these rules to `/app/game/escape.db`:

1. `rooms.hint` — set every hint to SQL `NULL`.
2. `rooms.is_locked` — `0` for the entry room (`id = 1`), `1` for every other room.
3. `allowed_commands` — keep a row only if **every** program in its command is a coreutils utility from the README, none of its programs is in the denylist `rm, dd, shred, chroot, runcon`, and the full command string contains no `*` or `?`. Delete every other row.
4. `challenge_checks` — after step 3, delete any row whose `(room_id, expected_command)` does not exactly match a surviving `allowed_commands` row (same `room_id`, identical `command` string).
5. `rooms.cmd_digest` — after step 3, set it to the lowercase hex SHA-256 of that room's surviving `allowed_commands.command` values, sorted ascending by byte value and joined with a single `\n` (no trailing newline). A room with no surviving commands gets the SHA-256 of the empty string.

Don't alter the table schemas and don't renumber the rooms, and leave every other column value and every row you aren't told to change exactly as seeded. Use whatever tooling you like — the `sqlite3` CLI is installed, and if you'd rather drive it from Java there's a SQLite JDBC driver under `/opt/java-libs/`. When you're done I'll verify by comparing a canonical dump of the three tables (`rooms` by `id`; `allowed_commands` and `challenge_checks` by their contents) against the expected hardened state.
