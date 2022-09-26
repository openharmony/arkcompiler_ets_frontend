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

#include "asyncGeneratorFunctionBuilder.h"

#include <compiler/base/catchTable.h>
#include <compiler/core/pandagen.h>
#include <ir/base/scriptFunction.h>

namespace panda::es2panda::compiler {
void AsyncGeneratorFunctionBuilder::Prepare(const ir::ScriptFunction *node)
{
    RegScope rs(pg_);
    VReg callee = FunctionReg(node);
    VReg completionType = pg_->AllocReg();
    VReg completionValue = pg_->AllocReg();

    pg_->CreateAsyncGeneratorObj(node, callee);
    pg_->StoreAccumulator(node, funcObj_);

    pg_->SetLabel(node, catchTable_->LabelSet().TryBegin());

    pg_->LoadConst(node, Constant::JS_UNDEFINED);
    SuspendResumeExecution(node, completionType, completionValue);
}

void AsyncGeneratorFunctionBuilder::CleanUp(const ir::ScriptFunction *node) const
{
    const auto &labelSet = catchTable_->LabelSet();

    RegScope rs(pg_);
    VReg value = pg_->AllocReg();

    pg_->SetLabel(node, labelSet.TryEnd());
    pg_->SetLabel(node, labelSet.CatchBegin());
    pg_->StoreAccumulator(node, value);
    pg_->AsyncGeneratorReject(node, funcObj_, value);
    pg_->EmitReturn(node);
    pg_->SetLabel(node, labelSet.CatchEnd());
}

void AsyncGeneratorFunctionBuilder::DirectReturn(const ir::AstNode *node) const
{
    RegScope rs(pg_);
    VReg retVal = pg_->AllocReg();
    VReg canSuspend = pg_->AllocReg();

    pg_->StoreAccumulator(node, retVal);
    pg_->StoreConst(node, canSuspend, Constant::JS_TRUE);

    pg_->AsyncGeneratorResolve(node, funcObj_, retVal, canSuspend);
    pg_->EmitReturn(node);
}

void AsyncGeneratorFunctionBuilder::ImplicitReturn(const ir::AstNode *node) const
{
    pg_->LoadConst(node, Constant::JS_UNDEFINED);
    DirectReturn(node);
}

void AsyncGeneratorFunctionBuilder::Yield(const ir::AstNode *node)
{
    RegScope rs(pg_);
    VReg value = pg_->AllocReg();
    VReg done = pg_->AllocReg();
    VReg completionType = pg_->AllocReg();
    VReg completionValue = pg_->AllocReg();

    auto *notNextCompletion = pg_->AllocLabel();
    auto *notThrowCompletion = pg_->AllocLabel();

    pg_->StoreAccumulator(node, value);
    pg_->StoreConst(node, done, Constant::JS_FALSE);
    pg_->AsyncGeneratorResolve(node, funcObj_, value, done);
    SuspendResumeExecution(node, completionType, completionValue);

    // .next(value)
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::NEXT));
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, completionType, notNextCompletion);
    pg_->LoadAccumulator(node, completionValue);

    // .throw(value)
    pg_->SetLabel(node, notNextCompletion);
    pg_->LoadAccumulatorInt(node, static_cast<int32_t>(ResumeMode::THROW));
    pg_->Condition(node, lexer::TokenType::PUNCTUATOR_EQUAL, completionType, notThrowCompletion);
    pg_->LoadAccumulator(node, completionValue);
    pg_->EmitThrow(node);

    // .return(value)
    pg_->SetLabel(node, notThrowCompletion);
    pg_->LoadAccumulator(node, completionValue);
    pg_->EmitReturn(node);
}

IteratorType AsyncGeneratorFunctionBuilder::GeneratorKind() const
{
    return IteratorType::ASYNC;
}
}  // namespace panda::es2panda::compiler
