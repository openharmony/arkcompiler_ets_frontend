#!/bin/bash
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -x

# install and pack dependency arkanalyzer
cd ../arkanalyzer
npm install

cp package.json package.json.bak

sed -i '/postinstall/d' package.json
npm pack

TAR_FILE=$(find . -maxdepth 1 -name "arkanalyzer-*.tgz" -print0)
cd ../homecheck
npm install ../arkanalyzer/$TAR_FILE

# revert the project files
mv ../arkanalyzer/package.json.bak ../arkanalyzer/package.json
rm ../arkanalyzer/$TAR_FILE
