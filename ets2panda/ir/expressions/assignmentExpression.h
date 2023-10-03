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

#ifndef ES2PANDA_IR_EXPRESSION_ASSIGNMENT_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_ASSIGNMENT_EXPRESSION_H

#include "ir/expression.h"
#include "lexer/token/tokenType.h"

namespace panda::es2panda::ir {
class AssignmentExpression : public Expression {
public:
    explicit AssignmentExpression(Expression *left, Expression *right, lexer::TokenType assignment_operator)
        : AssignmentExpression(AstNodeType::ASSIGNMENT_EXPRESSION, left, right, assignment_operator)
    {
    }

    explicit AssignmentExpression(AstNodeType type, Expression *left, Expression *right,
                                  lexer::TokenType assignment_operator)
        : Expression(type), left_(left), right_(right), operator_(assignment_operator)
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

    Expression *Right()
    {
        return right_;
    }

    const Expression *Right() const
    {
        return right_;
    }

    lexer::TokenType OperatorType() const
    {
        return operator_;
    }

    lexer::TokenType SetOperatorType(lexer::TokenType token_type)
    {
        return operator_ = token_type;
    }

    binder::Variable *Target()
    {
        return target_;
    }

    binder::Variable *Target() const
    {
        return target_;
    }

    bool ConvertibleToAssignmentPattern(bool must_be_pattern = true);
    void CreateBinaryExpressionForRight(checker::ETSChecker *checker);

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompilePattern(compiler::PandaGen *pg) const;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *left_;
    Expression *right_;
    lexer::TokenType operator_;
    binder::Variable *target_ {};
    checker::Type *operation_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
