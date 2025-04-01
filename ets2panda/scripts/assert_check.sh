#!/bin/bash
# Copyright (c) 2025 Huawei Device Co., Ltd.
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

target_dir=$1/"ets_frontend/ets2panda"
excluded_dirs=("lsp" "test" "driver" "bindings" "scripts")
excluded_file="$target_dir/util/es2pandaMacros.h"

# Build exclude conditions for find
exclude_prune=()
for dir in "${excluded_dirs[@]}"; do
    exclude_prune+=(-path "*/$dir" -o)
done
unset 'exclude_prune[${#exclude_prune[@]}-1]'  # Remove last -o

# Find and process files
found_entries=$(find "$target_dir" \
    -type d \( "${exclude_prune[@]}" \) -prune -o \
    -type f ! -path "$excluded_file" \
    -exec grep -HnwE 'ASSERT|UNREACHABLE' {} +) || true

# Format output and exit
if [[ -n "$found_entries" ]]; then
    echo "ERROR: Depricated macroses ASSERT or UNREACHABLE found."
    echo "Please use ES2PANDA_ASSERT(_POS) or ES2PANDA_UNREACHABLE(_POS)."
    echo "It's better to use *_POS version of macroses to specify position in source code."
    echo "$found_entries"
    exit 1
else
    exit 0
fi