/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "assignmentExpression.h"

#include "compiler/base/lreference.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/memberExpression.h"

#include "checker/TSchecker.h"
#include "checker/ts/destructuringContext.h"
#include "checker/ets/typeRelationContext.h"

namespace ark::es2panda::ir {
bool AssignmentExpression::ConvertibleToAssignmentPattern(bool mustBePattern)
{
    bool convResult = true;

    switch (left_->Type()) {
        case AstNodeType::ARRAY_EXPRESSION: {
            convResult = left_->AsArrayExpression()->ConvertibleToArrayPattern();
            break;
        }
        case AstNodeType::SPREAD_ELEMENT: {
            convResult = mustBePattern && left_->AsSpreadElement()->ConvertibleToRest(false);
            break;
        }
        case AstNodeType::OBJECT_EXPRESSION: {
            convResult = left_->AsObjectExpression()->ConvertibleToObjectPattern();
            break;
        }
        case AstNodeType::ASSIGNMENT_EXPRESSION: {
            convResult = left_->AsAssignmentExpression()->ConvertibleToAssignmentPattern(mustBePattern);
            break;
        }
        case AstNodeType::META_PROPERTY_EXPRESSION:
        case AstNodeType::CHAIN_EXPRESSION: {
            convResult = false;
            break;
        }
        default: {
            break;
        }
    }

    if (mustBePattern) {
        SetType(AstNodeType::ASSIGNMENT_PATTERN);
    }

    if (!right_->IsAssignmentExpression()) {
        return convResult;
    }

    switch (right_->Type()) {
        case AstNodeType::ARRAY_EXPRESSION: {
            convResult = right_->AsArrayExpression()->ConvertibleToArrayPattern();
            break;
        }
        case AstNodeType::CHAIN_EXPRESSION:
        case AstNodeType::SPREAD_ELEMENT: {
            convResult = false;
            break;
        }
        case AstNodeType::OBJECT_EXPRESSION: {
            convResult = right_->AsObjectExpression()->ConvertibleToObjectPattern();
            break;
        }
        case AstNodeType::ASSIGNMENT_EXPRESSION: {
            convResult = right_->AsAssignmentExpression()->ConvertibleToAssignmentPattern(false);
            break;
        }
        default: {
            break;
        }
    }

    return convResult;
}

void AssignmentExpression::TransformChildren(const NodeTransformer &cb)
{
    left_ = cb(left_)->AsExpression();
    right_ = cb(right_)->AsExpression();
}

void AssignmentExpression::Iterate(const NodeTraverser &cb) const
{
    cb(left_);
    cb(right_);
}

void AssignmentExpression::Dump(ir::AstDumper *dumper) const
{
    if (type_ == AstNodeType::ASSIGNMENT_EXPRESSION) {
        dumper->Add({{"type", "AssignmentExpression"}, {"operator", operator_}, {"left", left_}, {"right", right_}});
    } else {
        dumper->Add({{"type", "AssignmentPattern"}, {"left", left_}, {"right", right_}});
    }
}

void AssignmentExpression::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(left_);
    left_->Dump(dumper);
    dumper->Add(" ");
    dumper->Add(TokenToString(operator_));
    dumper->Add(" ");
    ASSERT(right_);
    right_->Dump(dumper);
}

void AssignmentExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void AssignmentExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

void AssignmentExpression::CompilePattern(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    auto lref = compiler::JSLReference::Create(pg, left_, false);
    right_->Compile(pg);
    lref.SetValue();
}

checker::Type *AssignmentExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *AssignmentExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

AssignmentExpression::AssignmentExpression([[maybe_unused]] Tag const tag, AssignmentExpression const &other,
                                           Expression *const left, Expression *const right)
    : AssignmentExpression(other)
{
    left_ = left;
    if (left_ != nullptr) {
        left_->SetParent(this);
    }

    right_ = right;
    if (right_ != nullptr) {
        right_->SetParent(this);
    }
}

AssignmentExpression *AssignmentExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const left = left_ != nullptr ? left_->Clone(allocator, nullptr)->AsExpression() : nullptr;
    auto *const right = right_ != nullptr ? right_->Clone(allocator, nullptr)->AsExpression() : nullptr;

    if (auto *const clone = allocator->New<AssignmentExpression>(Tag {}, *this, left, right); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }

        clone->SetRange(Range());
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace ark::es2panda::ir