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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Migrate {

    static final Pattern ASSIGN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*=");
    static final Set<String> DENY =
            new HashSet<>(Arrays.asList("rm", "dd", "shred", "chroot", "runcon"));
    static Set<String> approved;

    // Quote/escape-aware canonical form: strip an unquoted, unescaped inline
    // comment, collapse runs of unquoted, unescaped whitespace to a single
    // space, trim such ends. Quotes/escapes and protected bytes are kept.
    static String canon(String s) {
        StringBuilder res = new StringBuilder();
        int n = s.length(), i = 0;
        boolean inS = false, inD = false, pend = false, boundary = true;
        while (i < n) {
            char ch = s.charAt(i);
            if (inS) {
                res.append(ch);
                if (ch == '\'') inS = false;
                boundary = false; i++; continue;
            }
            if (inD) {
                res.append(ch);
                if (ch == '"') inD = false;
                boundary = false; i++; continue;
            }
            if (ch == '\\') {
                if (pend && res.length() > 0) res.append(' ');
                pend = false;
                if (i + 1 < n) { res.append('\\'); res.append(s.charAt(i + 1)); i += 2; }
                else { res.append('\\'); i++; }
                boundary = false; continue;
            }
            if (ch == '\'' || ch == '"') {
                if (pend && res.length() > 0) res.append(' ');
                pend = false;
                if (ch == '\'') inS = true; else inD = true;
                res.append(ch); boundary = false; i++; continue;
            }
            if (Character.isWhitespace(ch)) { pend = true; boundary = true; i++; continue; }
            if (ch == '#' && boundary) break;
            if (pend && res.length() > 0) res.append(' ');
            pend = false; res.append(ch); boundary = false; i++;
        }
        return res.toString();
    }

    // Split s on unquoted, unescaped separators (whitespace when ws=true, else '|').
    static List<String> scanSplit(String s, boolean ws) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int n = s.length(), i = 0;
        boolean inS = false, inD = false;
        while (i < n) {
            char ch = s.charAt(i);
            if (inS) {
                cur.append(ch);
                if (ch == '\'') inS = false;
                i++; continue;
            }
            if (inD) {
                cur.append(ch);
                if (ch == '"') inD = false;
                i++; continue;
            }
            if (ch == '\\') {
                if (i + 1 < n) { cur.append('\\'); cur.append(s.charAt(i + 1)); i += 2; }
                else { cur.append('\\'); i++; }
                continue;
            }
            if (ch == '\'') { inS = true; cur.append(ch); i++; continue; }
            if (ch == '"') { inD = true; cur.append(ch); i++; continue; }
            boolean sep = ws ? Character.isWhitespace(ch) : (ch == '|');
            if (sep) { parts.add(cur.toString()); cur.setLength(0); i++; continue; }
            cur.append(ch); i++;
        }
        parts.add(cur.toString());
        return parts;
    }

    static String unquote(String t) {
        StringBuilder o = new StringBuilder();
        int n = t.length(), i = 0;
        boolean inS = false, inD = false;
        while (i < n) {
            char ch = t.charAt(i);
            if (inS) { if (ch == '\'') inS = false; else o.append(ch); i++; continue; }
            if (inD) { if (ch == '"') inD = false; else o.append(ch); i++; continue; }
            if (ch == '\\') { if (i + 1 < n) { o.append(t.charAt(i + 1)); i += 2; } else i++; continue; }
            if (ch == '\'') { inS = true; i++; continue; }
            if (ch == '"') { inD = true; i++; continue; }
            o.append(ch); i++;
        }
        return o.toString();
    }

    static boolean hasGlob(String s) {
        int n = s.length(), i = 0;
        boolean inS = false, inD = false;
        while (i < n) {
            char ch = s.charAt(i);
            if (inS) { if (ch == '\'') inS = false; i++; continue; }
            if (inD) { if (ch == '"') inD = false; i++; continue; }
            if (ch == '\\') { i += (i + 1 < n) ? 2 : 1; continue; }
            if (ch == '\'') { inS = true; i++; continue; }
            if (ch == '"') { inD = true; i++; continue; }
            if (ch == '*' || ch == '?') return true;
            i++;
        }
        return false;
    }

    static String basename(String t) {
        int slash = t.lastIndexOf('/');
        return slash >= 0 ? t.substring(slash + 1) : t;
    }

    static String stageProgram(String stage) {
        List<String> values = new ArrayList<>();
        for (String t : scanSplit(stage, true)) {
            if (!t.isEmpty()) values.add(unquote(t));
        }
        int i = 0;
        while (i < values.size() && ASSIGN.matcher(values.get(i)).find()) i++;
        if (i >= values.size()) return null;
        String prog = basename(values.get(i));
        if (prog.equals("env")) {
            i++;
            while (i < values.size()
                    && (values.get(i).startsWith("-") || ASSIGN.matcher(values.get(i)).find())) {
                i++;
            }
            if (i >= values.size()) return "env";
            prog = basename(values.get(i));
        }
        return prog;
    }

    static boolean isSafe(String command) {
        if (hasGlob(command)) return false;
        for (String stage : scanSplit(command, false)) {
            String prog = stageProgram(stage);
            if (prog == null || !approved.contains(prog) || DENY.contains(prog)) {
                return false;
            }
        }
        return true;
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String sha256Hex(String s) throws Exception {
        return toHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8")));
    }

    static String hmacSha256Hex(String key, String msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256"));
        return toHex(mac.doFinal(msg.getBytes("UTF-8")));
    }

    static void canonicalize(Connection c, String table, String col) throws Exception {
        Map<Integer, String> updates = new HashMap<>();
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, " + col + " FROM " + table)) {
            while (rs.next()) {
                updates.put(rs.getInt(1), canon(rs.getString(2)));
            }
        }
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE " + table + " SET " + col + " = ? WHERE id = ?")) {
            for (Map.Entry<Integer, String> e : updates.entrySet()) {
                ps.setString(1, e.getValue());
                ps.setInt(2, e.getKey());
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    public static void main(String[] args) throws Exception {
        String db = args[0];
        String listFile = args[1];

        approved = new HashSet<>();
        for (String line : Files.readAllLines(Paths.get(listFile))) {
            String t = line.trim();
            if (!t.isEmpty()) approved.add(t);
        }

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db)) {
            c.setAutoCommit(false);

            // Rule 1: canonicalize command columns.
            canonicalize(c, "allowed_commands", "command");
            canonicalize(c, "challenge_checks", "expected_command");
            canonicalize(c, "doors", "via_command");

            // Rule 2: wipe hints.
            try (Statement st = c.createStatement()) {
                st.executeUpdate("UPDATE rooms SET hint = NULL");
            }

            // Rule 3: whitelist allowed_commands.
            List<Integer> drop = new ArrayList<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT id, command FROM allowed_commands")) {
                while (rs.next()) {
                    if (!isSafe(rs.getString(2))) drop.add(rs.getInt(1));
                }
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "DELETE FROM allowed_commands WHERE id = ?")) {
                for (int id : drop) { ps.setInt(1, id); ps.addBatch(); }
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

            // Rule 5: recompute points for surviving challenge_checks.
            Map<Integer, Integer> pointUpdates = new HashMap<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery(
                         "SELECT id, expected_command FROM challenge_checks")) {
                while (rs.next()) {
                    String cmd = rs.getString(2);
                    int pts = 7 * scanSplit(cmd, false).size() + cmd.length();
                    pointUpdates.put(rs.getInt(1), pts);
                }
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE challenge_checks SET points = ? WHERE id = ?")) {
                for (Map.Entry<Integer, Integer> e : pointUpdates.entrySet()) {
                    ps.setInt(1, e.getValue());
                    ps.setInt(2, e.getKey());
                    ps.addBatch();
                }
                ps.executeBatch();
            }

            // Rule 6: delete non-usable doors.
            try (Statement st = c.createStatement()) {
                st.executeUpdate(
                    "DELETE FROM doors WHERE NOT EXISTS ("
                    + "SELECT 1 FROM allowed_commands a "
                    + "WHERE a.room_id = doors.from_room "
                    + "AND a.command = doors.via_command)");
            }

            // Rule 7: reachability from room 1 over surviving doors.
            Map<Integer, List<Integer>> adj = new HashMap<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT from_room, to_room FROM doors")) {
                while (rs.next()) {
                    adj.computeIfAbsent(rs.getInt(1), k -> new ArrayList<>()).add(rs.getInt(2));
                }
            }
            Set<Integer> reachable = new HashSet<>();
            ArrayDeque<Integer> queue = new ArrayDeque<>();
            reachable.add(1);
            queue.add(1);
            while (!queue.isEmpty()) {
                int u = queue.poll();
                for (int v : adj.getOrDefault(u, Collections.emptyList())) {
                    if (reachable.add(v)) queue.add(v);
                }
            }
            List<Integer> roomIds = new ArrayList<>();
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT id FROM rooms ORDER BY id")) {
                while (rs.next()) roomIds.add(rs.getInt(1));
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE rooms SET is_locked = ? WHERE id = ?")) {
                for (int roomId : roomIds) {
                    ps.setInt(1, reachable.contains(roomId) ? 0 : 1);
                    ps.setInt(2, roomId);
                    ps.addBatch();
                }
                ps.executeBatch();
            }

            // Rule 8: per-room cmd_digest over surviving commands.
            Map<Integer, String> digests = new HashMap<>();
            for (int roomId : roomIds) {
                List<String> cmds = new ArrayList<>();
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT command FROM allowed_commands WHERE room_id = ?")) {
                    ps.setInt(1, roomId);
                    try (ResultSet rs = ps.executeQuery()) {
                        while (rs.next()) cmds.add(rs.getString(1));
                    }
                }
                Collections.sort(cmds);
                String digest = sha256Hex(String.join("\n", cmds));
                digests.put(roomId, digest);
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE rooms SET cmd_digest = ? WHERE id = ?")) {
                    ps.setString(1, digest);
                    ps.setInt(2, roomId);
                    ps.executeUpdate();
                }
            }

            // Rule 9: signed manifest over the per-room digests.
            List<String> lines = new ArrayList<>();
            for (int roomId : roomIds) {
                lines.add(roomId + "=" + digests.get(roomId));
            }
            String manifest = hmacSha256Hex("shell-escape", String.join("\n", lines));
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE meta SET value = ? WHERE key = 'manifest'")) {
                ps.setString(1, manifest);
                ps.executeUpdate();
            }

            c.commit();
        }
        System.out.println("Migration complete.");
    }
}
JAVA

javac -cp "/opt/java-libs/*" -d "$WORK" "$WORK/Migrate.java"
java -cp "$WORK:/opt/java-libs/*" Migrate /app/game/escape.db "$WORK/allowed_utils.txt"
