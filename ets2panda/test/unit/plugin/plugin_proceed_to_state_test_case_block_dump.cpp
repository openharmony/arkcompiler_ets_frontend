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

#include <iostream>
#include <ostream>
#include <string>
#include <cstring>
#include "public/es2panda_lib.h"
#include "util.h"

// NOLINTBEGIN
static std::string source = R"(
class C {
    f(v: int) {
        switch (v) {
            case 1: {
                const x = 1;
                break;
            }
            case 2: {
                const x = 1;
                break;
            }
            default: {
                const x = 1;
                break;
            }
        }
    }
}
)";

static es2panda_Impl *impl = nullptr;

int main(int argc, char **argv)
{
    std::map<es2panda_ContextState, std::vector<std::function<bool(es2panda_Context *)>>> testFunctions;
    std::string dumpedSource {};
    testFunctions[ES2PANDA_STATE_CHECKED] = {[&dumpedSource](es2panda_Context *ctx) {
        dumpedSource = impl->AstNodeDumpEtsSrcConst(ctx, impl->ProgramAst(ctx, impl->ContextProgram(ctx)));
        std::cout << dumpedSource << std::endl;
        return true;
    }};
    ProccedToStatePluginTestData data = {argc, argv, &impl, testFunctions, true, source};
    auto testResult = RunAllStagesWithTestFunction(data);
    if (testResult != 0) {
        return testResult;
    }
    data.source = dumpedSource;
    data.testFunctions = {};
    // Rerun test on dumped source
    return RunAllStagesWithTestFunction(data);
}

// NOLINTEND
