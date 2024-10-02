#!/usr/bin/env bash
# Copyright (c) 2023-2024 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

usage() {
    echo "Usage: $0 path/to/panda/build/bin/es2panda path/to/tsproject [PANDA_RUN_PREFIX] panda/root"
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

rm -r -f "$BUILD"

ACTUAL=$(mktemp /tmp/actual.XXXXXX)
STDLIB="$PANDA_ROOT/plugins/ets/stdlib"
CMD="$PANDA_RUN_PREFIX $ES2PANDA --stdlib=$STDLIB --arktsconfig=$TSCONFIG"
$CMD 2> /dev/null
pushd "$TSCONFIG_DIR" &> /dev/null
find . -type f -name '*abc' | sort --version-sort > "$ACTUAL"
popd &> /dev/null

set +e
diff "$EXPECTED" "$ACTUAL"
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
    echo "diff $(realpath $EXPECTED) $(pwd)/actual.txt"
fi
rm "$ACTUAL"
rm -r -f "$BUILD"
exit $RES
