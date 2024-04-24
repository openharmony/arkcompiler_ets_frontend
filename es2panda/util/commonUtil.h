/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ES2PANDA_UTIL_COMMON_H
#define ES2PANDA_UTIL_COMMON_H

#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <string_view>

namespace panda::es2panda::util {
static const std::string NPM_ENTRIES = "npmEntries.txt";
static const std::string IS_COMMONJS = "isCommonjs";
static const std::string NORMALIZED_OHMURL_NOT_SO = "@normalized:N";
static const std::string MODULE_RECORD_IDX = "moduleRecordIdx";

static constexpr char NORMALIZED_OHMURL_SEPARATOR = '&';
static constexpr char NORMALIZED_OHMURL_PREFIX = '@';
static constexpr char SLASH_TAG = '/';

static constexpr size_t BUNDLE_NAME_POS = 2U;
static constexpr size_t NORMALIZED_IMPORT_POS = 3U;
static constexpr size_t VERSION_POS = 4U;

std::vector<std::string> SplitNormalizedOhmurl(const std::string &ohmurl);
bool IsExternalPkgNames(const std::string &ohmurl, const std::set<std::string> &externalPkgNames);
std::string GetRecordNameFromNormalizedOhmurl(const std::string &ohmurl);
std::string GetPkgNameFromNormalizedOhmurl(const std::string &ohmurl);

}  // namespace panda::es2panda::util

#endif