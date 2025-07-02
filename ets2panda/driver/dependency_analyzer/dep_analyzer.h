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

#ifndef ES2PANDA_DEPENDENCY_ANALYZER_H
#define ES2PANDA_DEPENDENCY_ANALYZER_H

#include "public/es2panda_lib.h"
#include "public/public.h"
#include "parser/parserImpl.h"
#include "util/options.h"
#include <iostream>
#include <vector>

struct DepAnalyzerArgs {
    std::string programName;
    std::string arktsconfig;
    std::vector<std::string> fileList;
};

class DepAnalyzer {
public:
    int AnalyzeDeps(int argc, const char **argv);
    int AnalyzeDepsForMultiFiles(const char *exec, std::vector<std::string> &fileList, std::string &arktsconfig);
    std::string ConvertPath(const std::string &path) const;
    void Dump(std::string &outFilePath);
    void Dump(std::ostream &ostr = std::cout);

    const std::vector<std::string> &GetSourcePaths()
    {
        return sourcePaths_;
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> &GetFileDirectDependencies()
    {
        return fileDirectDependencies_;
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> &GetFileDirectDependants()
    {
        return fileDirectDependants_;
    }

private:
    void AddImports(ark::es2panda::parser::ETSParser *parser);
    bool ShouldSkipFile(const std::string &filePath) const;
    void MergeFileDeps(ark::es2panda::parser::Program *mainProgram);

    std::vector<std::string> sourcePaths_;
    std::vector<std::string> skipPatterns_;
    std::unordered_map<std::string, std::unordered_set<std::string>> fileDirectDependencies_;
    std::unordered_map<std::string, std::unordered_set<std::string>> fileDirectDependants_;
};

#endif  // ES2PANDA_DEPENDENCY_ANALYZER_H
