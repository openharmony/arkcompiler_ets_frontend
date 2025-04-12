/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dep_analyzer.h"

static void FilterArgs(ark::Span<const char *const> args, int &newArgc, const char **&newArgv)
{
    ASSERT(args.size() > 1);
    std::vector<const char *> filteredArgs;
    filteredArgs.push_back(args[0]);
    for (size_t i = 1; i < args.size(); ++i) {
        if (std::strncmp(args[i], "--output", std::strlen("--output")) == 0) {
            continue;
        }
        filteredArgs.push_back(args[i]);
    }

    newArgc = static_cast<int>(filteredArgs.size());
    if (newArgc <= 0 || static_cast<size_t>(newArgc) > args.size()) {
        return;
    }
    newArgv = new const char *[newArgc];
    std::copy(filteredArgs.begin(), filteredArgs.end(), newArgv);
}

static std::string ParseOption(ark::Span<const char *const> args)
{
    ASSERT(args.size() > 1);
    for (size_t i = 1; i < args.size(); ++i) {
        if (std::strncmp(args[i], "--output", std::strlen("--output")) == 0) {
            if (std::strchr(args[i], '=') != nullptr) {
                std::string arg = args[i];
                return arg.substr(std::strlen("--output="));
            }
            return "./fileList.txt";
        }
    }
    return "";
}

int main(int argc, const char **argv)
{
    ark::Span<const char *const> args(argv, static_cast<size_t>(argc));
    std::string outFilePath {ParseOption(args)};
    int newArgc = 0;
    const char **newArgv = nullptr;
    FilterArgs(args, newArgc, newArgv);

    DepAnalyzer da;
    if (da.AnalyzeDeps(newArgc, newArgv) != 0) {
        return 1;
    }

    if (outFilePath.empty()) {
        da.Dump();
    } else {
        da.Dump(outFilePath);
    }
    return 0;
}
