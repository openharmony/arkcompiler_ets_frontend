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

#ifndef ES2PANDA_IR_EXPRESSION_BINARY_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_BINARY_EXPRESSION_H

#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/lexer/token/tokenType.h"

namespace panda::es2panda::ir {
class BinaryExpression : public Expression {
public:
    explicit BinaryExpression(Expression *left_expr, Expression *right_expr, lexer::TokenType operator_type)
        : Expression(AstNodeType::BINARY_EXPRESSION), left_(left_expr), right_(right_expr), operator_(operator_type)
    {
    }

    const Expression *Left() const
    {
        return left_;
    }

    Expression *Left()
    {
        return left_;
    }

    const Expression *Right() const
    {
        return right_;
    }

    Expression *Right()
    {
        return right_;
    }

    lexer::TokenType OperatorType() const
    {
        return operator_;
    }

    bool IsLogical() const
    {
        return operator_ <= lexer::TokenType::PUNCTUATOR_LOGICAL_AND;
    }

    void SetLeft(Expression *expr)
    {
        left_ = expr;
        SetStart(left_->Start());
    }

    void SetOperator(lexer::TokenType operator_type)
    {
        operator_ = operator_type;
        type_ = AstNodeType::BINARY_EXPRESSION;
    }

    checker::Type *OperationType()
    {
        return operation_type_;
    }

    void SetOperationType(checker::Type *const operation_type) noexcept
    {
        operation_type_ = operation_type;
    }

    const checker::Type *OperationType() const
    {
        return operation_type_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompileLogical(compiler::PandaGen *pg) const;
    void CompileLogical(compiler::ETSGen *etsg) const;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *left_;
    Expression *right_;
    lexer::TokenType operator_;
    checker::Type *operation_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
