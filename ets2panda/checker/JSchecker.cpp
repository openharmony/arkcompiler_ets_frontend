/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "JSchecker.h"

#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"

namespace panda::es2panda::checker {

bool JSChecker::StartChecker([[maybe_unused]] binder::Binder *binder, const CompilerOptions &options)
{
    Initialize(binder);
    binder->IdentifierAnalysis();

    if (options.dump_ast) {
        std::cout << Program()->Dump() << std::endl;
    }

    return !options.parse_only;
}

}  // namespace panda::es2panda::checker
