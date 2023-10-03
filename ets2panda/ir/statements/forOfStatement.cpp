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

#include "forOfStatement.h"

#include "binder/scope.h"
#include "compiler/base/iterators.h"
#include "compiler/base/lreference.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/expression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/superExpression.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/variableDeclaration.h"

namespace panda::es2panda::ir {
void ForOfStatement::Iterate(const NodeTraverser &cb) const
{
    cb(left_);
    cb(right_);
    cb(body_);
}

void ForOfStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add(
        {{"type", "ForOfStatement"}, {"await", is_await_}, {"left", left_}, {"right", right_}, {"body", body_}});
}

void ForOfStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    compiler::LocalRegScope decl_reg_scope(pg, Scope()->DeclScope()->InitScope());

    right_->Compile(pg);

    compiler::LabelTarget label_target(pg);
    auto iterator_type = is_await_ ? compiler::IteratorType::ASYNC : compiler::IteratorType::SYNC;
    compiler::Iterator iterator(pg, this, iterator_type);

    pg->SetLabel(this, label_target.ContinueTarget());

    iterator.Next();
    iterator.Complete();
    pg->BranchIfTrue(this, label_target.BreakTarget());

    iterator.Value();
    pg->StoreAccumulator(this, iterator.NextResult());

    auto lref = compiler::JSLReference::Create(pg, left_, false);

    {
        compiler::IteratorContext for_of_ctx(pg, iterator, label_target);
        pg->LoadAccumulator(this, iterator.NextResult());
        lref.SetValue();

        compiler::LoopEnvScope decl_env_scope(pg, Scope()->DeclScope());
        compiler::LoopEnvScope env_scope(pg, Scope(), {});
        body_->Compile(pg);
    }

    pg->Branch(this, label_target.ContinueTarget());
    pg->SetLabel(this, label_target.BreakTarget());
}

void ForOfStatement::Compile(compiler::ETSGen *etsg) const
{
    compiler::LocalRegScope decl_reg_scope(etsg, Scope()->DeclScope()->InitScope());

    checker::Type const *const expr_type = right_->TsType();
    ASSERT(expr_type->IsETSArrayType() || expr_type->IsETSStringType());

    right_->Compile(etsg);
    compiler::VReg obj_reg = etsg->AllocReg();
    etsg->StoreAccumulator(this, obj_reg);

    if (expr_type->IsETSArrayType()) {
        etsg->LoadArrayLength(this, obj_reg);
    } else {
        etsg->LoadStringLength(this);
    }

    compiler::VReg size_reg = etsg->AllocReg();
    etsg->StoreAccumulator(this, size_reg);

    compiler::LabelTarget label_target(etsg);
    auto label_ctx = compiler::LabelContext(etsg, label_target);

    etsg->BranchIfFalse(this, label_target.BreakTarget());

    compiler::VReg count_reg = etsg->AllocReg();
    etsg->MoveImmediateToRegister(this, count_reg, checker::TypeFlag::INT, static_cast<std::int32_t>(0));
    etsg->LoadAccumulatorInt(this, static_cast<std::int32_t>(0));

    auto lref = compiler::ETSLReference::Create(etsg, left_, false);
    etsg->SetLabel(this, label_target.ContinueTarget());

    if (right_->TsType()->IsETSArrayType()) {
        etsg->LoadArrayElement(this, obj_reg);
    } else {
        etsg->LoadStringChar(this, obj_reg, count_reg);
    }

    lref.SetValue();
    body_->Compile(etsg);

    etsg->IncrementImmediateRegister(this, count_reg, checker::TypeFlag::INT, static_cast<std::int32_t>(1));
    etsg->LoadAccumulator(this, count_reg);

    etsg->JumpCompareRegister<compiler::Jlt>(this, size_reg, label_target.ContinueTarget());
    etsg->SetLabel(this, label_target.BreakTarget());
}

checker::Type *ForOfStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const INVALID_SOURCE_EXPR_TYPE[] =
    "'For-of' statement source expression should be either a string or an array.";
static constexpr char const INVALID_CONST_ASSIGNMENT[] = "Cannot assign a value to a constant variable ";
static constexpr char const ITERATOR_TYPE_ABSENT[] = "Cannot obtain iterator type in 'for-of' statement.";
// NOLINTEND(modernize-avoid-c-arrays)

checker::Type *ForOfStatement::Check(checker::ETSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    checker::Type *const expr_type = right_->Check(checker);
    checker::Type *elem_type;

    if (expr_type == nullptr || (!expr_type->IsETSArrayType() && !expr_type->IsETSStringType())) {
        checker->ThrowTypeError(INVALID_SOURCE_EXPR_TYPE, right_->Start());
    } else if (expr_type->IsETSStringType()) {
        elem_type = checker->GetGlobalTypesHolder()->GlobalCharType();
    } else {
        elem_type = expr_type->AsETSArrayType()->ElementType()->Instantiate(checker->Allocator(), checker->Relation(),
                                                                            checker->GetGlobalTypesHolder());
        elem_type->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
    }

    left_->Check(checker);
    checker::Type *iter_type = nullptr;

    if (left_->IsIdentifier()) {
        if (auto *const variable = left_->AsIdentifier()->Variable(); variable != nullptr) {
            if (variable->Declaration()->IsConstDecl()) {
                checker->ThrowTypeError({INVALID_CONST_ASSIGNMENT, variable->Name()},
                                        variable->Declaration()->Node()->Start());
            }
        }
        iter_type = left_->AsIdentifier()->TsType();
    } else if (left_->IsVariableDeclaration()) {
        if (auto const &declarators = left_->AsVariableDeclaration()->Declarators(); !declarators.empty()) {
            if (auto const &for_iterator = declarators.front(); for_iterator->TsType() == nullptr) {
                if (auto *resolved = checker->FindVariableInFunctionScope(for_iterator->Id()->AsIdentifier()->Name());
                    resolved != nullptr) {
                    resolved->SetTsType(elem_type);
                    iter_type = elem_type;
                }
            } else {
                iter_type = for_iterator->TsType();
            }
        }
    }

    if (iter_type == nullptr) {
        checker->ThrowTypeError(ITERATOR_TYPE_ABSENT, left_->Start());
    }

    auto *const relation = checker->Relation();
    relation->SetFlags(checker::TypeRelationFlag::ASSIGNMENT_CONTEXT);
    relation->SetNode(checker->AllocNode<ir::SuperExpression>());  // Dummy node to avoid assertion!

    if (!relation->IsAssignableTo(elem_type, iter_type)) {
        std::stringstream ss {};
        ss << "Source element type '";
        elem_type->ToString(ss);
        ss << "' is not assignable to the loop iterator type '";
        iter_type->ToString(ss);
        ss << "'.";
        checker->ThrowTypeError(ss.str(), Start());
    }

    relation->SetNode(nullptr);
    relation->SetFlags(checker::TypeRelationFlag::NONE);

    body_->Check(checker);

    return nullptr;
}
}  // namespace panda::es2panda::ir
