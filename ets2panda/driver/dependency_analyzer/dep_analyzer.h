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

class DepAnalyzer {
public:
    int AnalyzeDeps(int argc, const char **argv);
    void Dump(std::string &outFilePath);
    void Dump(std::ostream &ostr = std::cout);

    const std::vector<std::string> &GetSourcePaths()
    {
        return sourcePaths_;
    }

private:
    void AddImports(ark::es2panda::parser::ETSParser *parser);

    std::vector<std::string> sourcePaths_;
};

#endif  // ES2PANDA_DEPENDENCY_ANALYZER_H
