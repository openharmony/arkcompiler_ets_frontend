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

#include "updateExpression.h"

#include "binder/variable.h"
#include "compiler/base/lreference.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/expressions/unaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"

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
    compiler::VReg operand_reg = pg->AllocReg();

    auto lref = compiler::JSLReference::Create(pg, argument_, false);
    lref.GetValue();

    pg->StoreAccumulator(this, operand_reg);
    pg->Unary(this, operator_, operand_reg);

    lref.SetValue();

    if (!IsPrefix()) {
        pg->ToNumber(this, operand_reg);
    }
}

void UpdateExpression::Compile(compiler::ETSGen *etsg) const
{
    auto lref = compiler::ETSLReference::Create(etsg, argument_, false);

    const auto argument_boxing_flags =
        static_cast<BoxingUnboxingFlags>(argument_->GetBoxingUnboxingFlags() & BoxingUnboxingFlags::BOXING_FLAG);
    const auto argument_unboxing_flags =
        static_cast<BoxingUnboxingFlags>(argument_->GetBoxingUnboxingFlags() & BoxingUnboxingFlags::UNBOXING_FLAG);

    if (prefix_) {
        argument_->SetBoxingUnboxingFlags(argument_unboxing_flags);
        lref.GetValue();
        etsg->Update(this, operator_);
        argument_->SetBoxingUnboxingFlags(argument_boxing_flags);
        etsg->ApplyConversion(argument_, argument_->TsType());
        lref.SetValue();
        return;
    }

    // workaround so argument_ does not get auto unboxed by lref.GetValue()
    argument_->SetBoxingUnboxingFlags(BoxingUnboxingFlags::NONE);
    lref.GetValue();

    compiler::RegScope rs(etsg);
    compiler::VReg original_value_reg = etsg->AllocReg();
    etsg->StoreAccumulator(argument_, original_value_reg);

    argument_->SetBoxingUnboxingFlags(argument_unboxing_flags);
    etsg->ApplyConversion(argument_, nullptr);
    etsg->Update(this, operator_);

    argument_->SetBoxingUnboxingFlags(argument_boxing_flags);
    etsg->ApplyConversion(argument_, argument_->TsType());
    lref.SetValue();

    etsg->LoadAccumulator(argument_, original_value_reg);
}

checker::Type *UpdateExpression::Check(checker::TSChecker *checker)
{
    checker::Type *operand_type = argument_->Check(checker);
    checker->CheckNonNullType(operand_type, Start());

    if (!operand_type->HasTypeFlag(checker::TypeFlag::VALID_ARITHMETIC_TYPE)) {
        checker->ThrowTypeError("An arithmetic operand must be of type 'any', 'number', 'bigint' or an enum type.",
                                Start());
    }

    checker->CheckReferenceExpression(
        argument_, "The operand of an increment or decrement operator must be a variable or a property access",
        "The operand of an increment or decrement operator may not be an optional property access");

    return checker->GetUnaryResultType(operand_type);
}

checker::Type *UpdateExpression::Check(checker::ETSChecker *checker)
{
    checker::Type *operand_type = argument_->Check(checker);
    if (argument_->IsIdentifier()) {
        checker->ValidateUnaryOperatorOperand(argument_->AsIdentifier()->Variable());
    } else {
        ASSERT(argument_->IsMemberExpression());
        binder::LocalVariable *prop_var = argument_->AsMemberExpression()->PropVar();
        if (prop_var != nullptr) {
            checker->ValidateUnaryOperatorOperand(prop_var);
        }
    }

    auto unboxed_type = checker->ETSBuiltinTypeAsPrimitiveType(operand_type);

    if (unboxed_type == nullptr || !unboxed_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
        checker->ThrowTypeError("Bad operand type, the type of the operand must be numeric type.", argument_->Start());
    }

    if (operand_type->IsETSObjectType()) {
        argument_->AddBoxingUnboxingFlag(checker->GetUnboxingFlag(unboxed_type) | checker->GetBoxingFlag(unboxed_type));
    }

    SetTsType(operand_type);
    return TsType();
}
}  // namespace panda::es2panda::ir
