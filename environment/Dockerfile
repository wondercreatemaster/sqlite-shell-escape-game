# Base image pinned to an immutable digest for reproducibility.
FROM python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7

# Base tooling: harbor recording utils + Java toolchain + sqlite CLI + fetch tools.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tmux \
        asciinema \
        default-jdk-headless \
        sqlite3 \
        wget \
        ca-certificates \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# SQLite JDBC driver on the classpath for the Java migration (version- and
# checksum-pinned for reproducibility).
RUN mkdir -p /opt/java-libs \
    && wget -q -O /opt/java-libs/sqlite-jdbc-3.46.1.3.jar \
       https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.46.1.3/sqlite-jdbc-3.46.1.3.jar \
    && echo "4a4832720a65eaf7f4d6fd7ede52087b994dc5633c076f9e994dc0c8b4b0b4fa  /opt/java-libs/sqlite-jdbc-3.46.1.3.jar" \
       | sha256sum -c -

# Directories for the app and the pristine seed.
RUN mkdir -p /app/game /opt/seed

# Staged GNU coreutils 9.5 release tarball (version- and checksum-pinned; there
# is no network access at run time).
RUN wget -q -O /app/coreutils-9.5.tar.gz \
       https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.gz \
    && echo "767ae6a22950ec42f3ba5f7c1de79dd27800ee8e9b8642da5dedb5974a1741e5  /app/coreutils-9.5.tar.gz" \
       | sha256sum -c -

# Build the insecure seed database from the pristine seed script.
COPY seed.sql /opt/seed/seed.sql
RUN sqlite3 /app/game/escape.db < /opt/seed/seed.sql

# Stage the binary policy blob the migration must parse (magic/version/CRC32).
COPY policy.bin /app/game/policy.bin

# Stage the policy dossier (change-log the migration mines parameters from).
COPY dossier.md /app/game/dossier.md

WORKDIR /app
