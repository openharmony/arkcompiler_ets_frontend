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

#ifndef ES2PANDA_IR_EXPRESSION_ASSIGNMENT_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_ASSIGNMENT_EXPRESSION_H

#include "ir/expression.h"
#include "lexer/token/tokenType.h"

namespace panda::es2panda::ir {
class AssignmentExpression : public Expression {
private:
    struct Tag {};

public:
    AssignmentExpression() = delete;
    ~AssignmentExpression() override = default;

    NO_COPY_OPERATOR(AssignmentExpression);
    NO_MOVE_SEMANTIC(AssignmentExpression);

    explicit AssignmentExpression(Expression *const left, Expression *const right,
                                  lexer::TokenType const assignment_operator)
        : AssignmentExpression(AstNodeType::ASSIGNMENT_EXPRESSION, left, right, assignment_operator)
    {
    }

    explicit AssignmentExpression(AstNodeType const type, Expression *const left, Expression *const right,
                                  lexer::TokenType const assignment_operator)
        : Expression(type), left_(left), right_(right), operator_(assignment_operator)
    {
    }

    explicit AssignmentExpression(Tag tag, AssignmentExpression const &other, Expression *left, Expression *right);

    [[nodiscard]] const Expression *Left() const noexcept
    {
        return left_;
    }

    [[nodiscard]] Expression *Left() noexcept
    {
        return left_;
    }

    [[nodiscard]] Expression *Right() noexcept
    {
        return right_;
    }

    [[nodiscard]] const Expression *Right() const noexcept
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

    [[nodiscard]] lexer::TokenType SetOperatorType(lexer::TokenType token_type) noexcept
    {
        return operator_ = token_type;
    }

    void SetResult(Expression *expr) noexcept
    {
        left_ = expr;
        SetStart(left_->Start());
    }

    [[nodiscard]] bool IsLogicalExtended() const noexcept
    {
        return operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_AND ||
               operator_ == lexer::TokenType::PUNCTUATOR_LOGICAL_OR;
    }

    [[nodiscard]] binder::Variable *Target() noexcept
    {
        return target_;
    }

    [[nodiscard]] binder::Variable *Target() const noexcept
    {
        return target_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    [[nodiscard]] bool ConvertibleToAssignmentPattern(bool must_be_pattern = true);

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompilePattern(compiler::PandaGen *pg) const;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

protected:
    AssignmentExpression(AssignmentExpression const &other) : Expression(static_cast<Expression const &>(other))
    {
        operator_ = other.operator_;
        target_ = other.target_;
        operation_type_ = other.operation_type_;
    }

private:
    Expression *left_ = nullptr;
    Expression *right_ = nullptr;
    Expression *result_ = nullptr;
    lexer::TokenType operator_;
    binder::Variable *target_ {};
    checker::Type *operation_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
