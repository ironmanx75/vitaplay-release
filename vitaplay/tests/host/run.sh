#!/bin/sh
# End-to-end protocol test on the host: builds src/ (minus Vita-only video/main) for this
# machine, runs it, and drives it with tools/FakePhone.java.
#
#   CC="zig cc" DEPS=/path/with/libmbed.a+libsodium.a+include-dirs tests/host/run.sh
#
# DEPS must contain libmbed.a, libsodium.a, mbedtls-3.6.5/include and
# libsodium-1.0.22/src/libsodium/include.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CC=${CC:-cc}
: "${DEPS:?set DEPS to the host mbedTLS/libsodium build directory}"
WORK=$(mktemp -d)
SERVER=""
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Copy the tree so source paths have no spaces (word splitting below).
mkdir -p "$WORK/tree/tests"
cp -R "$ROOT/src" "$WORK/tree/src"
cp -R "$ROOT/tests/host" "$WORK/tree/tests/host"
cd "$WORK/tree"
SOURCES=$(ls src/*.c | grep -v -e '/video.c$' -e '/main.c$')
# shellcheck disable=SC2086
$CC -O1 -g -std=gnu11 -DAIRPLAY_PORT=7700 -Wall -Wno-unused-parameter -Wno-format-truncation \
    -Itests/host/include -I"$DEPS/mbedtls-3.6.5/include" \
    -I"$DEPS/libsodium-1.0.22/src/libsodium/include" \
    $SOURCES tests/host/host_main.c "$DEPS/libmbed.a" "$DEPS/libsodium.a" \
    -lpthread -o "$WORK/host_vitaplay"

cd "$WORK"
java "$ROOT/tools/FakePhone.java" --gen-test-mfi "ux0:data/VitaPlay/offline-mfi" >/dev/null
./host_vitaplay 127.0.0.1 40 7141 > server.out 2>&1 &
SERVER=$!
sleep 1
cat server.out

STATUS=0
java "$ROOT/tools/FakePhone.java" 127.0.0.1:7700 "ux0:data/VitaPlay/offline-mfi/certificate.p7b" --relay-port 7141 || STATUS=$?
sleep 1
echo
echo "---- VitaPlay log ----"
cat "ux0:data/VitaPlay/log.txt"
exit $STATUS
