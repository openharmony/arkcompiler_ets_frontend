/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "conditionalExpression.h"

#include "compiler/base/condition.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
void ConditionalExpression::TransformChildren(const NodeTransformer &cb)
{
    test_ = cb(test_)->AsExpression();
    consequent_ = cb(consequent_)->AsExpression();
    alternate_ = cb(alternate_)->AsExpression();
}

void ConditionalExpression::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(consequent_);
    cb(alternate_);
}

void ConditionalExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add(
        {{"type", "ConditionalExpression"}, {"test", test_}, {"consequent", consequent_}, {"alternate", alternate_}});
}

template <typename CodeGen>
void CompileImpl(const ConditionalExpression *self, CodeGen *cg)
{
    auto *false_label = cg->AllocLabel();
    auto *end_label = cg->AllocLabel();

    compiler::Condition::Compile(cg, self->Test(), false_label);
    self->Consequent()->Compile(cg);
    cg->Branch(self, end_label);
    cg->SetLabel(self, false_label);
    self->Alternate()->Compile(cg);
    cg->SetLabel(self, end_label);
}

void ConditionalExpression::Compile(compiler::PandaGen *pg) const
{
    CompileImpl(this, pg);
}

void ConditionalExpression::Compile(compiler::ETSGen *etsg) const
{
    auto *false_label = etsg->AllocLabel();
    auto *end_label = etsg->AllocLabel();

    compiler::Condition::Compile(etsg, Test(), false_label);
    Consequent()->Compile(etsg);
    etsg->ApplyConversion(Consequent());
    etsg->Branch(this, end_label);
    etsg->SetLabel(this, false_label);
    Alternate()->Compile(etsg);
    etsg->ApplyConversion(Alternate());
    etsg->SetLabel(this, end_label);
}

checker::Type *ConditionalExpression::Check(checker::TSChecker *checker)
{
    checker::Type *test_type = test_->Check(checker);

    checker->CheckTruthinessOfType(test_type, test_->Start());
    checker->CheckTestingKnownTruthyCallableOrAwaitableType(test_, test_type, consequent_);

    checker::Type *consequent_type = consequent_->Check(checker);
    checker::Type *alternate_type = alternate_->Check(checker);

    return checker->CreateUnionType({consequent_type, alternate_type});
}

checker::Type *ConditionalExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker->CheckTruthinessOfType(test_);

    checker::Type *consequent_type = consequent_->Check(checker);
    checker::Type *alternate_type = alternate_->Check(checker);

    auto *primitive_consequent_type = checker->ETSBuiltinTypeAsPrimitiveType(consequent_type);
    auto *primitive_alter_type = checker->ETSBuiltinTypeAsPrimitiveType(alternate_type);

    if (primitive_consequent_type != nullptr && primitive_alter_type != nullptr) {
        if (checker->IsTypeIdenticalTo(consequent_type, alternate_type)) {
            SetTsType(checker->GetNonConstantTypeFromPrimitiveType(consequent_type));
        } else if (checker->IsTypeIdenticalTo(primitive_consequent_type, primitive_alter_type)) {
            checker->FlagExpressionWithUnboxing(consequent_->TsType(), primitive_consequent_type, consequent_);
            checker->FlagExpressionWithUnboxing(alternate_->TsType(), primitive_alter_type, alternate_);

            SetTsType(primitive_consequent_type);
        } else if (primitive_consequent_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) &&
                   primitive_alter_type->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC)) {
            checker->FlagExpressionWithUnboxing(consequent_->TsType(), primitive_consequent_type, consequent_);
            checker->FlagExpressionWithUnboxing(alternate_->TsType(), primitive_alter_type, alternate_);

            SetTsType(
                checker->ApplyConditionalOperatorPromotion(checker, primitive_consequent_type, primitive_alter_type));
        } else {
            checker->ThrowTypeError("Type error", this->range_.start);
        }
    } else {
        if (!(consequent_type->IsETSArrayType() || alternate_type->IsETSArrayType()) &&
            !(consequent_type->IsETSObjectType() && alternate_type->IsETSObjectType())) {
            checker->ThrowTypeError("Type error", this->range_.start);
        } else {
            checker->Relation()->SetNode(consequent_);
            auto builtin_conseq_type = checker->PrimitiveTypeAsETSBuiltinType(consequent_type);
            auto builtin_alternate_type = checker->PrimitiveTypeAsETSBuiltinType(alternate_type);

            if (builtin_conseq_type == nullptr) {
                builtin_conseq_type = consequent_type;
            }

            if (builtin_alternate_type == nullptr) {
                builtin_alternate_type = alternate_type;
            }

            SetTsType(checker->FindLeastUpperBound(builtin_conseq_type, builtin_alternate_type));
        }
    }

    return TsType();
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *ConditionalExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const test = test_ != nullptr ? test_->Clone(allocator) : nullptr;
    auto *const consequent = consequent_ != nullptr ? consequent_->Clone(allocator) : nullptr;
    auto *const alternate = alternate_ != nullptr ? alternate_->Clone(allocator) : nullptr;

    if (auto *const clone = allocator->New<ConditionalExpression>(test, consequent, alternate); clone != nullptr) {
        if (test != nullptr) {
            test->SetParent(clone);
        }
        if (consequent != nullptr) {
            consequent->SetParent(clone);
        }
        if (alternate != nullptr) {
            alternate->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
