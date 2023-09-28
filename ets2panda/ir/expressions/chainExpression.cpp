/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "chainExpression.h"

#include "plugins/ecmascript/es2panda/ir/expressions/callExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/compiler/base/optionalChain.h"
#include "plugins/ecmascript/es2panda/compiler/core/regScope.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"

namespace panda::es2panda::ir {
void ChainExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expression_);
}

void ChainExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ChainExpression"}, {"expression", expression_}});
}

void ChainExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    compiler::OptionalChain chain(pg, this);
    expression_->Compile(pg);
}

void ChainExpression::CompileToReg(compiler::PandaGen *pg, compiler::VReg &obj_reg) const
{
    compiler::OptionalChain chain(pg, this);

    if (expression_->IsMemberExpression()) {
        obj_reg = pg->AllocReg();
        expression_->AsMemberExpression()->CompileToReg(pg, obj_reg);
    } else {
        obj_reg = compiler::VReg::Invalid();
        expression_->Compile(pg);
    }
}

checker::Type *ChainExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return expression_->Check(checker);
}

checker::Type *ChainExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
