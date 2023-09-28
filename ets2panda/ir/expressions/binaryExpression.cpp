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

#include "binaryExpression.h"

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/compiler/core/function.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/compiler/core/regScope.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/lexer/token/tokenType.h"

namespace panda::es2panda::ir {
void BinaryExpression::Iterate(const NodeTraverser &cb) const
{
    cb(left_);
    cb(right_);
}

void BinaryExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", IsLogical() ? "LogicalExpression" : "BinaryExpression"},
                 {"operator", operator_},
                 {"left", left_},
                 {"right", right_}});
}

void BinaryExpression::CompileLogical(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg lhs = pg->AllocReg();

    ASSERT(operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND ||
           operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR ||
           operator_ == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING);

    auto *skip_right = pg->AllocLabel();
    auto *end_label = pg->AllocLabel();

    // left -> acc -> lhs -> toboolean -> acc -> bool_lhs
    left_->Compile(pg);
    pg->StoreAccumulator(this, lhs);

    if (operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        pg->ToBoolean(this);
        pg->BranchIfFalse(this, skip_right);
    } else if (operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR) {
        pg->ToBoolean(this);
        pg->BranchIfTrue(this, skip_right);
    } else if (operator_ == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING) {
        pg->BranchIfCoercible(this, skip_right);
    }

    // left is true/false(and/or) then right -> acc
    right_->Compile(pg);
    pg->Branch(this, end_label);

    // left is false/true(and/or) then lhs -> acc
    pg->SetLabel(this, skip_right);
    pg->LoadAccumulator(this, lhs);
    pg->SetLabel(this, end_label);
}

void BinaryExpression::Compile(compiler::PandaGen *pg) const
{
    if (IsLogical()) {
        CompileLogical(pg);
        return;
    }

    if (operator_ == lexer::TokenType::KEYW_IN && left_->IsIdentifier() && left_->AsIdentifier()->IsPrivateIdent()) {
        compiler::RegScope rs(pg);
        compiler::VReg ctor = pg->AllocReg();
        const auto &name = left_->AsIdentifier()->Name();
        compiler::Function::LoadClassContexts(this, pg, ctor, name);
        right_->Compile(pg);
        pg->ClassPrivateFieldIn(this, ctor, name);
        return;
    }

    compiler::RegScope rs(pg);
    compiler::VReg lhs = pg->AllocReg();

    left_->Compile(pg);
    pg->StoreAccumulator(this, lhs);
    right_->Compile(pg);

    pg->Binary(this, operator_, lhs);
}

void BinaryExpression::Compile(compiler::ETSGen *etsg) const
{
    if (etsg->TryLoadConstantExpression(this)) {
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, operation_type_);

    if (IsLogical()) {
        CompileLogical(etsg);
        etsg->ApplyConversion(this, operation_type_);
        return;
    }

    compiler::RegScope rs(etsg);
    compiler::VReg lhs = etsg->AllocReg();

    if (operator_ == lexer::TokenType::PUNCTUATOR_PLUS &&
        (left_->TsType()->IsETSStringType() || right_->TsType()->IsETSStringType())) {
        etsg->BuildString(this);
        return;
    }

    left_->Compile(etsg);
    etsg->ApplyConversionAndStoreAccumulator(left_, lhs, operation_type_);
    right_->Compile(etsg);
    etsg->ApplyConversion(right_, operation_type_);
    if (operator_ >= lexer::TokenType::PUNCTUATOR_LEFT_SHIFT &&
        operator_ <= lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT) {
        etsg->ApplyCast(right_, operation_type_);
    }

    etsg->Binary(this, operator_, lhs);
}

void BinaryExpression::CompileLogical(compiler::ETSGen *etsg) const
{
    auto *end_label = etsg->AllocLabel();

    left_->Compile(etsg);
    etsg->ApplyConversion(left_, operation_type_);

    if (operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
        etsg->BranchIfFalse(this, end_label);
    } else if (operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR) {
        etsg->BranchIfTrue(this, end_label);
    } else {
        ASSERT(operator_ == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING);
        etsg->BranchIfNotNull(this, end_label);
    }

    right_->Compile(etsg);
    etsg->ApplyConversion(right_, operation_type_);

    etsg->SetLabel(this, end_label);
}

checker::Type *BinaryExpression::Check(checker::TSChecker *checker)
{
    auto *left_type = left_->Check(checker);
    auto *right_type = right_->Check(checker);

    switch (operator_) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            return checker->CheckBinaryOperator(left_type, right_type, left_, right_, this, operator_);
        }
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            return checker->CheckPlusOperator(left_type, right_type, left_, right_, this, operator_);
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            return checker->CheckCompareOperator(left_type, right_type, left_, right_, this, operator_);
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            if (checker->IsTypeEqualityComparableTo(left_type, right_type) ||
                checker->IsTypeEqualityComparableTo(right_type, left_type)) {
                return checker->GlobalBooleanType();
            }

            checker->ThrowBinaryLikeError(operator_, left_type, right_type, Start());
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            return checker->CheckInstanceofExpression(left_type, right_type, right_, this);
        }
        case lexer::TokenType::KEYW_IN: {
            return checker->CheckInExpression(left_type, right_type, left_, right_, this);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            return checker->CheckAndOperator(left_type, right_type, left_);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            return checker->CheckOrOperator(left_type, right_type, left_);
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            // TODO(Csaba Repasi): Implement checker for nullish coalescing
            return checker->GlobalAnyType();
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            checker->CheckAssignmentOperator(operator_, left_, left_type, right_type);
            return right_type;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return nullptr;
}

checker::Type *BinaryExpression::Check(checker::ETSChecker *checker)
{
    checker::Type *new_ts_type {nullptr};
    std::tie(new_ts_type, operation_type_) = checker->CheckBinaryOperator(left_, right_, operator_, Start());
    SetTsType(new_ts_type);
    return TsType();
}
}  // namespace panda::es2panda::ir
