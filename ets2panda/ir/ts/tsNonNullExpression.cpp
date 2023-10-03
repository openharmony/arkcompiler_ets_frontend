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

#include "tsNonNullExpression.h"

#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void TSNonNullExpression::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(expr_);
}

void TSNonNullExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSNonNullExpression"}, {"expression", expr_}});
}

void TSNonNullExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void TSNonNullExpression::Compile(compiler::ETSGen *etsg) const
{
    compiler::RegScope rs(etsg);

    expr_->Compile(etsg);

    if (etsg->GetAccumulatorType()->IsETSNullType()) {
        etsg->EmitNullPointerException(this);
        return;
    }

    auto arg = etsg->AllocReg();
    etsg->StoreAccumulator(this, arg);
    etsg->LoadAccumulator(this, arg);

    auto end_label = etsg->AllocLabel();

    etsg->BranchIfNotNull(this, end_label);
    etsg->EmitNullPointerException(this);

    etsg->SetLabel(this, end_label);
    etsg->LoadAccumulator(this, arg);
}

checker::Type *TSNonNullExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *TSNonNullExpression::Check(checker::ETSChecker *checker)
{
    auto expr_type = expr_->Check(checker);

    if (!expr_type->IsNullableType()) {
        checker->ThrowTypeError("Bad operand type, the operand of the non-null expression must be a nullable type",
                                expr_->Start());
    }

    auto non_null_type =
        expr_type->Instantiate(checker->Allocator(), checker->Relation(), checker->GetGlobalTypesHolder());
    non_null_type->RemoveTypeFlag(checker::TypeFlag::NULLABLE);

    SetTsType(non_null_type);
    return TsType();
}
}  // namespace panda::es2panda::ir
