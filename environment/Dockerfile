FROM python:3.13-slim-bookworm

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

# Cache verifier wheels so tests/test.sh can install them at test time (offline).
RUN mkdir -p /opt/wheels \
    && python -m pip download --only-binary=:all: --dest /opt/wheels \
       pytest==8.4.1 \
       pytest-json-ctrf==0.3.5

# Pinned SQLite JDBC driver on the classpath for the Java migration.
RUN mkdir -p /opt/java-libs \
    && wget -q -O /opt/java-libs/sqlite-jdbc-3.46.1.3.jar \
       https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.46.1.3/sqlite-jdbc-3.46.1.3.jar

# Directories for the app and the pristine seed.
RUN mkdir -p /app/game /opt/seed

# Staged GNU coreutils 9.5 release tarball (there is no network access at run time).
RUN wget -q -O /app/coreutils-9.5.tar.gz \
       https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.gz

# Build the insecure seed database from the pristine seed script.
COPY seed.sql /opt/seed/seed.sql
RUN sqlite3 /app/game/escape.db < /opt/seed/seed.sql

WORKDIR /app
