/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "plugin_conversion_rule_test.h"

#include <iostream>
#include <fstream>
#include <sstream>

namespace {
bool HasContainRelation(const std::string &searchStr, const std::string &content)
{
    return content.find(searchStr) != std::string::npos;
}
}  // namespace

namespace test::utils {
PluginConversionRuleTest::PluginConversionRuleTest()
{
    const std::string pluginLibImplPath {"../../../generated/es2panda_lib/es2panda_lib_impl.inc"};
    ReadStringFromFile(pluginLibImplPath);
}

std::string PluginConversionRuleTest::RemoveWhitespace(const std::string &str)
{
    std::string result;
    for (char elem : str) {
        if (std::isspace(static_cast<unsigned char>(elem)) == 0) {
            result += elem;
        }
    }
    return result;
}

bool PluginConversionRuleTest::HasMatched(const std::string &searchStr) const
{
    return HasContainRelation(searchStr, cApiImplFileStr_);
}

void PluginConversionRuleTest::ReadStringFromFile(const std::string &filePath)
{
    std::filesystem::path cApiImplFileRelativePath {filePath};
    auto cApiImplFilePath = std::filesystem::current_path() / cApiImplFileRelativePath;
    std::ifstream fileStream(cApiImplFilePath, std::ios::in);
    if (!fileStream.is_open()) {
        std::cerr << "Failed to open file " << cApiImplFilePath << std::endl;
        cApiImplFileStr_ = "";
        return;
    }

    std::stringstream strStream;
    strStream << fileStream.rdbuf();
    cApiImplFileStr_ = RemoveWhitespace(strStream.str());
}
}  // namespace test::utils
