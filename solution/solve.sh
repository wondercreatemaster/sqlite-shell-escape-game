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
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class Migrate {

    static final Pattern ASSIGN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*=");
    static Set<String> approved;
    static final Set<String> DENY =
            new HashSet<>(Arrays.asList("rm", "dd", "shred", "chroot", "runcon"));

    static String basename(String t) {
        int slash = t.lastIndexOf('/');
        return slash >= 0 ? t.substring(slash + 1) : t;
    }

    // The program of a single pipeline stage, or null if none.
    static String stageProgram(String stage) {
        String s = stage.trim();
        String[] toks = s.isEmpty() ? new String[0] : s.split("\\s+");
        int i = 0;
        while (i < toks.length && ASSIGN.matcher(toks[i]).find()) {
            i++;
        }
        if (i >= toks.length) {
            return null;
        }
        String prog = basename(toks[i]);
        if (prog.equals("env")) {
            i++;
            while (i < toks.length
                    && (toks[i].startsWith("-") || ASSIGN.matcher(toks[i]).find())) {
                i++;
            }
            if (i >= toks.length) {
                return "env";
            }
            prog = basename(toks[i]);
        }
        return prog;
    }

    static boolean isSafe(String command) {
        if (command.indexOf('*') >= 0 || command.indexOf('?') >= 0) {
            return false;
        }
        for (String stage : command.split("\\|", -1)) {
            String prog = stageProgram(stage);
            if (prog == null || !approved.contains(prog) || DENY.contains(prog)) {
                return false;
            }
        }
        return true;
    }

    static String sha256Hex(String s) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String db = args[0];
        String listFile = args[1];

        approved = new HashSet<>();
        for (String line : Files.readAllLines(Paths.get(listFile))) {
            String t = line.trim();
            if (!t.isEmpty()) {
                approved.add(t);
            }
        }

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
                    if (!isSafe(rs.getString(2))) {
                        drop.add(rs.getInt(1));
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

            // Rule 5: recompute rooms.cmd_digest over surviving commands.
            List<Integer> roomIds = new ArrayList<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT id FROM rooms ORDER BY id")) {
                while (rs.next()) {
                    roomIds.add(rs.getInt(1));
                }
            }
            for (int roomId : roomIds) {
                List<String> cmds = new ArrayList<>();
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT command FROM allowed_commands WHERE room_id = ?")) {
                    ps.setInt(1, roomId);
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) {
                            cmds.add(rs.getString(1));
                        }
                    }
                }
                Collections.sort(cmds);
                String digest = sha256Hex(String.join("\n", cmds));
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE rooms SET cmd_digest = ? WHERE id = ?")) {
                    ps.setString(1, digest);
                    ps.setInt(2, roomId);
                    ps.executeUpdate();
                }
            }

            c.commit();
        }
        System.out.println("Migration complete.");
    }
}
JAVA

javac -cp "/opt/java-libs/*" -d "$WORK" "$WORK/Migrate.java"
java -cp "$WORK:/opt/java-libs/*" Migrate /app/game/escape.db "$WORK/allowed_utils.txt"
