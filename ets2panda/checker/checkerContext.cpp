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

#include "ETSchecker.h"

namespace ark::es2panda::checker {

CheckerContext::CheckerContext(Checker *checker, CheckerStatus newStatus, ETSObjectType const *containingClass,
                               Signature *containingSignature)
    : parent_(checker),
      status_(newStatus),
      capturedVars_(parent_->Allocator()->Adapter()),
      smartCasts_(parent_->Allocator()->Adapter()),
      containingClass_(containingClass),
      containingSignature_(containingSignature),
      testSmartCasts_(parent_->Allocator()->Adapter())
{
}

SmartCastTypes CheckerContext::CloneTestSmartCasts(bool const clearData) noexcept
{
    if (testSmartCasts_.empty()) {
        return std::nullopt;
    }

    SmartCastTestArray smartCasts {};
    smartCasts.reserve(testSmartCasts_.size());

    for (auto [variable, types] : testSmartCasts_) {
        if (types.first != nullptr || types.second != nullptr) {
            smartCasts.emplace_back(variable, types.first, types.second);
        }
    }

    if (clearData) {
        ClearTestSmartCasts();
    }

    return std::make_optional(smartCasts);
}

SmartCastArray CheckerContext::CloneSmartCasts(bool const clearData) noexcept
{
    SmartCastArray smartCasts {};

    if (!smartCasts_.empty()) {
        smartCasts.reserve(smartCasts_.size());

        for (auto const [variable, type] : smartCasts_) {
            smartCasts.emplace_back(variable, type);
        }
    }

    if (clearData) {
        ClearSmartCasts();
    }

    return smartCasts;
}

void CheckerContext::RestoreSmartCasts(SmartCastArray const &prevSmartCasts) noexcept
{
    smartCasts_.clear();
    if (!prevSmartCasts.empty()) {
        for (auto [variable, type] : prevSmartCasts) {
            smartCasts_.emplace(variable, type);
        }
    }
}

void CheckerContext::RemoveSmartCasts(SmartCastArray const &otherSmartCasts) noexcept
{
    if (!smartCasts_.empty()) {
        auto it = smartCasts_.begin();
        while (it != smartCasts_.end()) {
            if (std::find_if(otherSmartCasts.begin(), otherSmartCasts.end(), [&it](auto const &item) -> bool {
                    return item.first == it->first;
                }) == otherSmartCasts.end()) {
                it = smartCasts_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

checker::Type *CheckerContext::CombineTypes(checker::Type *const typeOne, checker::Type *const typeTwo) const noexcept
{
    ASSERT(typeOne != nullptr && typeTwo != nullptr);
    auto *const checker = parent_->AsETSChecker();

    if (checker->Relation()->IsIdenticalTo(typeOne, typeTwo)) {
        // no type change is required
        return nullptr;
    }

    return checker->CreateETSUnionType({typeOne, typeTwo});
}

void CheckerContext::CombineSmartCasts(SmartCastArray &alternateSmartCasts) noexcept
{
    auto *const checker = parent_->AsETSChecker();

    auto smartCast = alternateSmartCasts.begin();
    while (smartCast != alternateSmartCasts.end()) {
        auto const currentCast = smartCasts_.find(smartCast->first);
        if (currentCast == smartCasts_.end()) {
            // Remove smart cast that doesn't present in the current set.
            smartCast = alternateSmartCasts.erase(smartCast);
            continue;
        }

        // Smart type was modified
        if (auto *const smartType = CombineTypes(smartCast->second, currentCast->second); smartType != nullptr) {
            // Remove it or set to new value
            if (checker->Relation()->IsIdenticalTo(currentCast->first->TsType(), smartType)) {
                smartCasts_.erase(currentCast);
                smartCast = alternateSmartCasts.erase(smartCast);
                continue;
            }

            currentCast->second = smartType;
        }
        ++smartCast;
    }

    // Remove smart casts that don't present in the alternate set.
    RemoveSmartCasts(alternateSmartCasts);
}

// Second return value shows if the 'IN_LOOP' flag should be cleared on exit from the loop (case of nested loops).
std::pair<SmartCastArray, bool> CheckerContext::EnterLoop() noexcept
{
    bool const clearFlag = !IsInLoop();
    if (clearFlag) {
        status_ |= CheckerStatus::IN_LOOP;
    }

    return {CloneSmartCasts(true), clearFlag};
}

void CheckerContext::ExitLoop(SmartCastArray &prevSmartCasts, bool const clearFlag) noexcept
{
    if (clearFlag) {
        status_ &= ~CheckerStatus::IN_LOOP;
    }

    //  Now we don't process smart casts inside the loops correctly, thus just combine them on exit from the loop.
    CombineSmartCasts(prevSmartCasts);
}

//  Check that the expression is a part of logical OR/AND or unary negation operators chain
//  (other cases are not interested)
bool CheckerContext::IsInValidChain(ir::AstNode const *parent) noexcept
{
    while (parent != nullptr && !parent->IsIfStatement() && !parent->IsConditionalExpression()) {
        if (parent->IsBinaryExpression()) {
            auto const operation = parent->AsBinaryExpression()->OperatorType();
            if (operation != lexer::TokenType::PUNCTUATOR_LOGICAL_OR &&
                operation != lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
                return false;
            }
        } else if (parent->IsUnaryExpression()) {
            if (parent->AsUnaryExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
                return false;
            }
        } else {
            return false;
        }
        parent = parent->Parent();
    }
    return parent != nullptr;
}

void CheckerContext::CheckIdentifierSmartCastCondition(ir::Identifier const *const identifier) noexcept
{
    if (!IsInTestExpression()) {
        return;
    }

    auto const *const variable = identifier->Variable();
    ASSERT(variable != nullptr);

    //  Smart cast for extended conditional check can be applied only to the variables of reference types.
    if (auto const *const variableType = variable->TsType(); !variableType->IsETSReferenceType()) {
        return;
    }

    if (!IsInValidChain(identifier->Parent())) {
        return;
    }

    ASSERT(testCondition_.variable == nullptr);
    if (identifier->TsType()->PossiblyETSNullish()) {
        testCondition_ = {variable, parent_->AsETSChecker()->GlobalETSNullType(), true, false};
    }
}

void CheckerContext::CheckUnarySmartCastCondition(ir::UnaryExpression const *const unaryExpression) noexcept
{
    if (!IsInTestExpression() || unaryExpression->OperatorType() != lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK) {
        return;
    }

    auto const *const argument = unaryExpression->Argument();
    if (argument == nullptr || (!argument->IsIdentifier() && !argument->IsBinaryExpression())) {
        return;
    }

    if (!IsInValidChain(unaryExpression->Parent())) {
        return;
    }

    if (testCondition_.variable != nullptr) {
        testCondition_.negate = !testCondition_.negate;
    }
}

void CheckerContext::CheckBinarySmartCastCondition(ir::BinaryExpression *const binaryExpression) noexcept
{
    if (!IsInTestExpression() || !IsInValidChain(binaryExpression->Parent())) {
        return;
    }

    if (auto const operatorType = binaryExpression->OperatorType(); operatorType == lexer::TokenType::KEYW_INSTANCEOF) {
        ASSERT(testCondition_.variable == nullptr);
        if (binaryExpression->Left()->IsIdentifier()) {
            testCondition_ = {binaryExpression->Left()->AsIdentifier()->Variable(),
                              binaryExpression->Right()->TsType()};
        }
    } else if (operatorType == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL ||
               operatorType == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
               operatorType == lexer::TokenType::PUNCTUATOR_EQUAL ||
               operatorType == lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        ASSERT(testCondition_.variable == nullptr);
        CheckSmartCastEqualityCondition(binaryExpression);
    }
}

//  Extracted just to avoid large length and depth of method 'CheckBinarySmartCastCondition()'.
void CheckerContext::CheckSmartCastEqualityCondition(ir::BinaryExpression *const binaryExpression) noexcept
{
    varbinder::Variable const *variable = nullptr;
    checker::Type *testedType = nullptr;
    auto const operatorType = binaryExpression->OperatorType();

    bool strict = operatorType == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
                  operatorType == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL;

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

    if (binaryExpression->Left()->IsIdentifier()) {
        getTestedType(binaryExpression->Left()->AsIdentifier(), binaryExpression->Right());
    }

    if (testedType == nullptr && binaryExpression->Right()->IsIdentifier()) {
        getTestedType(binaryExpression->Right()->AsIdentifier(), binaryExpression->Left());
    }

    if (testedType != nullptr) {
        bool const negate = operatorType == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL ||
                            operatorType == lexer::TokenType::PUNCTUATOR_NOT_EQUAL;

        if (testedType->DefinitelyETSNullish()) {
            testCondition_ = {variable, testedType, negate, strict};
        } else if (!negate || !strict) {
            // NOTE: we cannot say anything about variable from the expressions like 'x !== "str"'
            testedType = parent_->AsETSChecker()->ResolveSmartType(testedType, variable->TsType());
            testCondition_ = {variable, testedType, negate, strict};
        }
    }
}

void CheckerContext::ClearTestSmartCasts() noexcept
{
    testCondition_ = {};
    testSmartCasts_.clear();
    operatorType_ = lexer::TokenType::EOS;
}

checker::Type *CheckerContext::GetSmartCast(varbinder::Variable const *const variable) const noexcept
{
    if (IsInTestExpression()) {
        if (operatorType_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND) {
            if (auto const it = testSmartCasts_.find(variable);
                it != testSmartCasts_.end() && it->second.first != nullptr) {
                return it->second.first;
            }
        } else if (operatorType_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR) {
            if (auto const it = testSmartCasts_.find(variable);
                it != testSmartCasts_.end() && it->second.second != nullptr) {
                return it->second.second;
            }
        }
    }

    auto const it = smartCasts_.find(variable);
    return it == smartCasts_.end() ? nullptr : it->second;
}

}  // namespace ark::es2panda::checker
