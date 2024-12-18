#!/bin/bash
# Copyright (c) 2024 Huawei Device Co., Ltd.
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

# Install typescript from third_party/typescript
# Must run this script in arkguard root directory.

set -ex

if [ -z "${NEXUS_REPO}" ]; then
    echo "Please set NEXUS_REPO"
    echo "export NEXUS_REPO=nexus.example.com:1234"
    exit 1
fi

HUAWEI_MIRROR="${HUAWEI_MIRROR:-https://repo.huaweicloud.com/repository/npm/}"
KOALA_REGISTRY="${KOALA_REGISTRY:-https://$NEXUS_REPO/repository/koala-npm/}"

function do_checkout() {
    local repo=$1
    local rev=$2
    local dest=$3
    local patch=$4
    [ -n "${repo}" ] || exit 1
    [ -n "${rev}" ] || exit 1
    [ -n "${dest}" ] || exit 1
    mkdir -p "${dest}"
    pushd "${dest}" || exit 1
        git init && git remote add origin "${repo}"
        # NOTE(titova): add repeat
        git fetch --depth 1 origin "${rev}" || {
            echo "(Some error occurred while fetching rev: ${rev}"
            exit 1
        } && {
            git checkout FETCH_HEAD || exit 1
            [ -n "${patch}" ] && git apply "${patch}"
        }
    popd >/dev/null 2>&1 || exit 1
}

GIT_URL=https://gitee.com/openharmony-sig/arkcompiler_ets_frontend.git
DEST=koala-sig
do_checkout "${GIT_URL}" panda_rev_4-workarounds "${DEST}"

cd "${DEST}" || exit 1

npm config set package-lock false
npm config set strict-ssl false
# npm config set lockfile false
npm config set registry "${HUAWEI_MIRROR}"
npm config set @koalaui:registry "${KOALA_REGISTRY}"
npm config set @panda:registry "https://$NEXUS_REPO/repository/koala-npm/"
npm config set @ohos:registry "https://repo.harmonyos.com/npm/"
if [ -z "${KOALA_REPO}" ] ; then
    npm config set "//$NEXUS_REPO/repository/koala-npm/:_auth=$KOALA_TOKEN"
fi

npm i

# NOTE(ttitova) need to fix it in es2panda
for config in $(find . -name 'arktsconfig*.json') ; do
# out_dir=$(awk -F ':' ' $1 ~ "outDir" { sub(/,/, "", $2) ; print $2 }' $config)
mkdir -p $(dirname "${config}")/build/abc
done

pushd incremental/tools/fast-arktsc/ || exit
npm i
popd >/dev/null 2>&1 || exit 1

pushd incremental/tools/panda/ || exit 1
if [ -z "${PANDA_SDK_TARBALL}" ] ; then
npm run panda:sdk:install
else
npm install "${PANDA_SDK_TARBALL}"
fi
popd >/dev/null 2>&1 || exit 1

pushd arkoala/arkui-common/ || exit 1
KOALA_BZ=1 npm run ohos-sdk
popd >/dev/null 2>&1 || exit 1

pushd arkoala-arkts || exit 1
npm run trivial:all:node:ci
popd >/dev/null 2>&1 || exit 1

exit 0
