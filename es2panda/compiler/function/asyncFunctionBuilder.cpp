/*
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

#include "asyncFunctionBuilder.h"

#include <compiler/core/pandagen.h>
#include <compiler/base/catchTable.h>
#include <ir/base/scriptFunction.h>

namespace panda::es2panda::compiler {

void AsyncFunctionBuilder::DirectReturn(const ir::AstNode *node) const
{
    RegScope rs(pg_);
    VReg retVal = pg_->AllocReg();
    VReg canSuspend = pg_->AllocReg();

    pg_->StoreAccumulator(node, retVal);
    pg_->LoadConst(node, Constant::JS_TRUE);
    pg_->StoreAccumulator(node, canSuspend);
    pg_->AsyncFunctionResolve(node, funcObj_, retVal, canSuspend);
    pg_->LoadAccumulator(node, retVal);
    pg_->EmitReturn(node);
}

void AsyncFunctionBuilder::ImplicitReturn(const ir::AstNode *node) const
{
    pg_->LoadConst(node, Constant::JS_UNDEFINED);
    DirectReturn(node);
}

void AsyncFunctionBuilder::Prepare(const ir::ScriptFunction *node)
{
    pg_->AsyncFunctionEnter(node);
    pg_->StoreAccumulator(node, funcObj_);
    pg_->SetLabel(node, catchTable_->LabelSet().TryBegin());
}

void AsyncFunctionBuilder::CleanUp(const ir::ScriptFunction *node) const
{
    RegScope rs(pg_);
    const auto &labelSet = catchTable_->LabelSet();

    pg_->SetLabel(node, labelSet.TryEnd());
    pg_->SetLabel(node, labelSet.CatchBegin());
    VReg exception = pg_->AllocReg();
    VReg canSuspend = pg_->AllocReg();
    pg_->StoreAccumulator(node, exception);
    pg_->StoreConst(node, canSuspend, Constant::JS_TRUE);
    pg_->AsyncFunctionReject(node, funcObj_, exception, canSuspend);
    pg_->EmitReturn(node);
    pg_->SetLabel(node, labelSet.CatchEnd());
}
}  // namespace panda::es2panda::compiler
