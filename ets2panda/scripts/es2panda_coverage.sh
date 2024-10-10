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

# Huawei Technologies Co.,Ltd.

set -e

for ARGUMENT in "$@"
do
case "$ARGUMENT" in
    --binary-dir=*)
    PANDA_BINARY_ROOT="${ARGUMENT#*=}"
    ;;
    --root-dir=*)
    PANDA_ROOT="${ARGUMENT#*=}"
    ;;
esac
done

python $PANDA_ROOT/tools/es2panda/scripts/test_runner.py \
    --builddir $PANDA_BINARY_ROOT --arkdir $PANDA_ROOT --all

gcov $PANDA_BINARY_ROOT/tools/es2panda/CMakeFiles/es2panda-lib.dir/*/*

if [ -x "$(command -v gcovr)" ]; then
    echo "gcovr found"
    gcovr --version
    gcovr -v -r $PANDA_ROOT/tools/es2panda/ \
        -e $PANDA_ROOT/tools/es2panda/test \
        --object-directory=$PANDA_BINARY_ROOT --html-details --html -o report.html

else
    echo "gcovr not found"
    exit 1
fi

exit 0
