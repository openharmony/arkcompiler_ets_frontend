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

#ifndef ES2PANDA_IR_EXPRESSION_BINARY_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_BINARY_EXPRESSION_H

#include "ir/expression.h"
#include "lexer/token/tokenType.h"

namespace panda::es2panda::ir {
class BinaryExpression : public Expression {
public:
    BinaryExpression() = delete;
    ~BinaryExpression() override = default;

    NO_COPY_SEMANTIC(BinaryExpression);
    NO_MOVE_SEMANTIC(BinaryExpression);

    explicit BinaryExpression(Expression *const left, Expression *const right, lexer::TokenType const operator_type)
        : Expression(AstNodeType::BINARY_EXPRESSION), left_(left), right_(right), operator_(operator_type)
    {
    }

    [[nodiscard]] const Expression *Left() const noexcept
    {
        return left_;
    }

    [[nodiscard]] Expression *Left() noexcept
    {
        return left_;
    }

    [[nodiscard]] const Expression *Right() const noexcept
    {
        return right_;
    }

    [[nodiscard]] Expression *Right() noexcept
    {
        return right_;
    }

    [[nodiscard]] const Expression *Result() const noexcept
    {
        return result_;
    }

    [[nodiscard]] Expression *Result() noexcept
    {
        return result_;
    }

    [[nodiscard]] lexer::TokenType OperatorType() const noexcept
    {
        return operator_;
    }

    [[nodiscard]] bool IsLogical() const noexcept
    {
        return operator_ <= lexer::TokenType::PUNCTUATOR_LOGICAL_AND;
    }

    [[nodiscard]] bool IsLogicalExtended() const noexcept
    {
        return operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND ||
               operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR;
    }

    void SetLeft(Expression *expr) noexcept
    {
        left_ = expr;
        SetStart(left_->Start());
    }

    void SetResult(Expression *expr) noexcept
    {
        left_ = expr;
        SetStart(left_->Start());
    }

    void SetOperator(lexer::TokenType operator_type) noexcept
    {
        operator_ = operator_type;
        type_ = AstNodeType::BINARY_EXPRESSION;
    }

    [[nodiscard]] checker::Type *OperationType() noexcept
    {
        return operation_type_;
    }

    void SetOperationType(checker::Type *const operation_type) noexcept
    {
        operation_type_ = operation_type;
    }

    [[nodiscard]] const checker::Type *OperationType() const noexcept
    {
        return operation_type_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompileLogical(compiler::PandaGen *pg) const;
    void CompileLogical(compiler::ETSGen *etsg) const;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *left_ = nullptr;
    Expression *right_ = nullptr;
    Expression *result_ = nullptr;
    lexer::TokenType operator_;
    checker::Type *operation_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
