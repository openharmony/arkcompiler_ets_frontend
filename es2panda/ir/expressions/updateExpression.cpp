/**
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "updateExpression.h"

#include <compiler/base/lreference.h>
#include <compiler/core/pandagen.h>
#include <ir/astDump.h>

namespace panda::es2panda::ir {

void UpdateExpression::Iterate(const NodeTraverser &cb) const
{
    cb(argument_);
}

void UpdateExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "UpdateExpression"}, {"operator", operator_}, {"prefix", prefix_}, {"argument", argument_}});
}

void UpdateExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg operandReg = pg->AllocReg();

    compiler::LReference lref = compiler::LReference::CreateLRef(pg, argument_, false);
    lref.GetValue();

    if (!IsPrefix()) {
        pg->StoreAccumulator(this, operandReg);
        pg->ToNumeric(this, operandReg);
    }

    pg->StoreAccumulator(this, operandReg);
    pg->Unary(this, operator_, operandReg);

    lref.SetValue();

    if (!IsPrefix()) {
        pg->LoadAccumulator(this, operandReg);
    }
}


void UpdateExpression::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    argument_ = std::get<ir::AstNode *>(cb(argument_))->AsExpression();
}

}  // namespace panda::es2panda::ir
