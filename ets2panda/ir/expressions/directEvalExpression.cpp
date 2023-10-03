

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

#include "directEvalExpression.h"

#include "util/helpers.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/regScope.h"

namespace panda::es2panda::ir {
void DirectEvalExpression::Compile(compiler::PandaGen *pg) const
{
    if (arguments_.empty()) {
        pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
        return;
    }

    compiler::RegScope rs(pg);
    bool contains_spread = util::Helpers::ContainSpreadElement(arguments_);
    if (contains_spread) {
        [[maybe_unused]] compiler::VReg args_obj = CreateSpreadArguments(pg);
        pg->LoadObjByIndex(this, 0);
    } else {
        compiler::VReg arg0 = pg->AllocReg();
        auto iter = arguments_.cbegin();
        (*iter++)->Compile(pg);
        pg->StoreAccumulator(this, arg0);

        while (iter != arguments_.cend()) {
            (*iter++)->Compile(pg);
        }

        pg->LoadAccumulator(this, arg0);
    }

    pg->DirectEval(this, parser_status_);
}
}  // namespace panda::es2panda::ir
