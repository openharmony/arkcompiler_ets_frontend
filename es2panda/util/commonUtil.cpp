/**
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

#include "commonUtil.h"

#include <algorithm>

namespace panda::es2panda::util {
std::vector<std::string> Split(const std::string &str, const char delimiter)
{
    std::string normalizedImport {};
    std::string pkgName {};
    std::vector<std::string> items;

    size_t start = 0;
    size_t pos = str.find(delimiter);
    while (pos != std::string::npos) {
        std::string item = str.substr(start, pos - start);
        items.emplace_back(item);
        start = pos + 1;
        pos = str.find(delimiter, start);
    }
    std::string tail = str.substr(start);
    items.emplace_back(tail);

    return items;
}

std::string GetPkgNameFromNormalizedOhmurl(const std::string &ohmurl)
{
    std::string normalizedImport {};
    std::string pkgName {};
    auto items = Split(ohmurl, NORMALIZED_OHMURL_SEPARATOR);

    normalizedImport = items[NORMALIZED_IMPORT_POS];
    size_t pos = normalizedImport.find(SLASH_TAG);
    if (pos != std::string::npos) {
        pkgName = normalizedImport.substr(0, pos);
    }
    if (normalizedImport[0] == NORMALIZED_OHMURL_PREFIX) {
        pos = normalizedImport.find(SLASH_TAG, pos + 1);
        if (pos != std::string::npos) {
            pkgName = normalizedImport.substr(0, pos);
        }
    }
    return pkgName;
}

std::string GetRecordNameFromNormalizedOhmurl(const std::string &ohmurl)
{
    // format of recordName: "<bundleName>&normalizedImport&<version>"
    std::string recordName {};
    auto items = Split(ohmurl, NORMALIZED_OHMURL_SEPARATOR);

    recordName += items[BUNDLE_NAME_POS] + NORMALIZED_OHMURL_SEPARATOR + items[NORMALIZED_IMPORT_POS] +
        NORMALIZED_OHMURL_SEPARATOR + items[VERSION_POS];
    return recordName;
}

bool IsExternalPkgNames(const std::string &ohmurl, const std::set<std::string> &externalPkgNames)
{
    auto pkgName = GetPkgNameFromNormalizedOhmurl(ohmurl);
    if (std::find(externalPkgNames.begin(), externalPkgNames.end(), pkgName) != externalPkgNames.end()) {
        return true;
    }
    return false;
}

} // namespace panda::es2panda::util