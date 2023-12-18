/**
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/srcDump.h"
#include "ir/visitor/AstVisitor.h"

namespace ark::es2panda::ir {
void BinaryExpression::TransformChildren(const NodeTransformer &cb)
{
    left_ = cb(left_)->AsExpression();
    right_ = cb(right_)->AsExpression();
}

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

void BinaryExpression::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(left_ != nullptr);
    ASSERT(right_ != nullptr);
    dumper->Add("(");
    left_->Dump(dumper);
    dumper->Add(" ");
    dumper->Add(TokenToString(operator_));
    dumper->Add(" ");
    right_->Dump(dumper);
    dumper->Add(")");
}

void BinaryExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void BinaryExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *BinaryExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *BinaryExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

BinaryExpression *BinaryExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const left = left_ != nullptr ? left_->Clone(allocator, nullptr)->AsExpression() : nullptr;
    auto *const right = right_ != nullptr ? right_->Clone(allocator, nullptr)->AsExpression() : nullptr;

    if (auto *const clone = allocator->New<BinaryExpression>(left, right, operator_); clone != nullptr) {
        if (operationType_ != nullptr) {
            clone->SetOperationType(operationType_);
        }

        if (right != nullptr) {
            right->SetParent(clone);
        }

        if (left != nullptr) {
            left->SetParent(clone);
        }

        if (parent != nullptr) {
            clone->SetParent(parent);
        }

        clone->SetRange(Range());
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

//  Extracted just to avoid large length and depth of method 'CheckSmartCastCondition()'.
void BinaryExpression::CheckSmartCastEqualityCondition(checker::ETSChecker *checker)
{
    varbinder::Variable const *variable = nullptr;
    checker::Type *testedType = nullptr;
    bool strict = operator_ == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
                  operator_ == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL;

    // extracted just to avoid extra nested level
    auto const getTestedType = [&variable, &testedType, &strict](ir::Identifier const *const identifier,
                                                                 ir::Expression *const expression) -> void {
        ASSERT(identifier != nullptr && expression != nullptr);
        variable = identifier->Variable();
        if (expression->IsLiteral()) {
            testedType = expression->TsType();
            if (!expression->IsNullLiteral() && !expression->IsUndefinedLiteral()) {
                strict = false;
            }
        }
    };

    if (left_->IsIdentifier()) {
        getTestedType(left_->AsIdentifier(), right_);
    }

    if (testedType == nullptr && right_->IsIdentifier()) {
        getTestedType(right_->AsIdentifier(), left_);
    }

    if (testedType != nullptr) {
        bool const negate = operator_ == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
                            operator_ == lexer::TokenType::PUNCTUATOR_NOT_EQUAL;

        if (testedType->DefinitelyETSNullish()) {
            smartCastCondition_ = {variable, testedType, negate, strict};
        } else if (!negate || !strict) {
            // NOTE: we cannot say anything about variable from the expressions like 'x !== "str"'
            testedType = checker->ResolveSmartType(testedType, variable->TsType());
            smartCastCondition_ = {variable, testedType, negate, strict};
        }
    }
}

void BinaryExpression::CheckSmartCastCondition(checker::ETSChecker *checker)
{
    if (operator_ == lexer::TokenType::KEYW_INSTANCEOF) {
        if (left_->IsIdentifier()) {
            smartCastCondition_ = {left_->AsIdentifier()->Variable(), right_->TsType()};
        }
    } else if (operator_ == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL ||
               operator_ == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
               operator_ == lexer::TokenType::PUNCTUATOR_EQUAL || operator_ == lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        CheckSmartCastEqualityCondition(checker);
    }
}
}  // namespace ark::es2panda::ir
