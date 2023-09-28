/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "generatorFunctionBuilder.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/base/catchTable.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"

namespace panda::es2panda::compiler {
void GeneratorFunctionBuilder::Prepare(const ir::ScriptFunction *node) const
{
    VReg callee = FunctionReg(node);

    pg_->CreateGeneratorObj(node, callee);
    pg_->StoreAccumulator(node, func_obj_);
    pg_->SuspendGenerator(node, func_obj_);
    pg_->SetLabel(node, catch_table_->LabelSet().TryBegin());
}

void GeneratorFunctionBuilder::CleanUp(const ir::ScriptFunction *node) const
{
    const auto &label_set = catch_table_->LabelSet();

    pg_->SetLabel(node, label_set.TryEnd());
    pg_->SetLabel(node, label_set.CatchBegin());
    pg_->GeneratorComplete(node, func_obj_);
    pg_->EmitThrow(node);
    pg_->SetLabel(node, label_set.CatchEnd());
}

void GeneratorFunctionBuilder::DirectReturn(const ir::AstNode *node) const
{
    pg_->GeneratorComplete(node, func_obj_);
    pg_->CreateIterResultObject(node, true);
    pg_->EmitReturn(node);
}

void GeneratorFunctionBuilder::ImplicitReturn(const ir::AstNode *node) const
{
    pg_->LoadConst(node, Constant::JS_UNDEFINED);
    DirectReturn(node);
}

void GeneratorFunctionBuilder::Yield(const ir::AstNode *node)
{
    RegScope rs(pg_);
    VReg completion_type = pg_->AllocReg();
    VReg completion_value = pg_->AllocReg();

    pg_->CreateIterResultObject(node, false);
    pg_->GeneratorYield(node, func_obj_);
    SuspendResumeExecution(node, completion_type, completion_value);

    HandleCompletion(node, completion_type, completion_value);
}
}  // namespace panda::es2panda::compiler
