#!/bin/bash
set -euo pipefail

WORK=/app/work
mkdir -p "$WORK"

# 1) Extract the coreutils source tarball and pull the vetted utility list out of
#    its top-level README (the program block that follows the header line).
tar -xzf /app/coreutils-9.5.tar.gz -C "$WORK"
README="$WORK/coreutils-9.5/README"

awk '
  /programs that can be built/ { grab=1; next }
  grab && /[^[:space:]]/       { started=1; print }
  grab && started==1 && /^[[:space:]]*$/ { exit }
' "$README" \
  | tr -d '[]' \
  | tr -s ' \t' '\n' \
  | sed '/^[[:space:]]*$/d' \
  | sort -u > "$WORK/allowed_utils.txt"

# 2) Apply the hardening rules to the SQLite database via a Java (JDBC) migration.
cat > "$WORK/Migrate.java" <<'JAVA'
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Migrate {

    // program = basename of the first whitespace-separated token of the command.
    static String program(String cmd) {
        String s = cmd.trim();
        int i = 0;
        while (i < s.length() && !Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        String first = s.substring(0, i);
        int slash = first.lastIndexOf('/');
        return slash >= 0 ? first.substring(slash + 1) : first;
    }

    public static void main(String[] args) throws Exception {
        String db = args[0];
        String listFile = args[1];

        Set<String> approved = new HashSet<>();
        for (String line : Files.readAllLines(Paths.get(listFile))) {
            String t = line.trim();
            if (!t.isEmpty()) {
                approved.add(t);
            }
        }
        Set<String> deny = new HashSet<>(
                Arrays.asList("rm", "dd", "shred", "chroot", "runcon"));

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db)) {
            c.setAutoCommit(false);

            // Rule 1 & 2: room hardening.
            try (Statement st = c.createStatement()) {
                st.executeUpdate("UPDATE rooms SET hint = NULL");
                st.executeUpdate(
                    "UPDATE rooms SET is_locked = CASE WHEN id = 1 THEN 0 ELSE 1 END");
            }

            // Rule 3: whitelist allowed_commands.
            List<Integer> drop = new ArrayList<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery(
                         "SELECT id, command FROM allowed_commands")) {
                while (rs.next()) {
                    int id = rs.getInt(1);
                    String cmd = rs.getString(2);
                    boolean wildcard = cmd.indexOf('*') >= 0 || cmd.indexOf('?') >= 0;
                    String prog = program(cmd);
                    boolean keep = !wildcard
                            && approved.contains(prog)
                            && !deny.contains(prog);
                    if (!keep) {
                        drop.add(id);
                    }
                }
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "DELETE FROM allowed_commands WHERE id = ?")) {
                for (int id : drop) {
                    ps.setInt(1, id);
                    ps.addBatch();
                }
                ps.executeBatch();
            }

            // Rule 4: prune orphan challenge_checks.
            try (Statement st = c.createStatement()) {
                st.executeUpdate(
                    "DELETE FROM challenge_checks WHERE NOT EXISTS ("
                    + "SELECT 1 FROM allowed_commands a "
                    + "WHERE a.room_id = challenge_checks.room_id "
                    + "AND a.command = challenge_checks.expected_command)");
            }

            c.commit();
        }
        System.out.println("Migration complete.");
    }
}
JAVA

javac -cp "/opt/java-libs/*" -d "$WORK" "$WORK/Migrate.java"
java -cp "$WORK:/opt/java-libs/*" Migrate /app/game/escape.db "$WORK/allowed_utils.txt"
