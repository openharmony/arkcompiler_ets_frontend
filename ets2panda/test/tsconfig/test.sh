#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

usage() {
    echo "Usage: $0 /path/to/panda/build/bin/es2panda /path/to/tsproject [PANDA_RUN_PREFIX]"
}

ensure_exists() {
    if [ ! -f "$1" ]; then
        echo "Error: No such file: '$1'"
        usage
        exit 1
    fi
}

ES2PANDA="$1"
TSCONFIG_DIR="$2"
PANDA_RUN_PREFIX="$3"
TSCONFIG="$TSCONFIG_DIR"/tsconfig.json
EXPECTED="$TSCONFIG_DIR"/expected.txt
BUILD="$TSCONFIG_DIR"/build
PANDA_ROOT="$4"

ensure_exists "$TSCONFIG"
ensure_exists "$ES2PANDA"
ensure_exists "$EXPECTED"

rm -rf "$BUILD"

ACTUAL=$(mktemp /tmp/actual.XXXXXX)
STDLIB="$PANDA_ROOT/plugins/ets/stdlib"
CMD="$PANDA_RUN_PREFIX $ES2PANDA --stdlib=$STDLIB --arktsconfig=$TSCONFIG"
$CMD 2> /dev/null
pushd "$TSCONFIG_DIR" &> /dev/null
find . -type f -name '*abc' | sort --version-sort > "$ACTUAL"
popd &> /dev/null

set +e
/usr/bin/diff "$EXPECTED" "$ACTUAL"
RES=$?
set -e
if [ "$RES" -ne 0 ]; then
    echo "Expected:"
    cat "$EXPECTED"
    echo "Actual:"
    cat "$ACTUAL"
    echo "How to reproduce:"
    echo "(cd $(pwd) && $CMD)"
    echo "(cd $(realpath $TSCONFIG_DIR) && find . -type f -name '*abc' | sort > $(pwd)/actual.txt)"
    echo "/usr/bin/diff $(realpath $EXPECTED) $(pwd)/actual.txt"
fi
rm "$ACTUAL"
rm -r "$BUILD"
exit $RES
