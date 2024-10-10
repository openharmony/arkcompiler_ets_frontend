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

#ifndef ES2PANDA_IR_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_H

#include "ir/astNode.h"
#include "ir/typed.h"

namespace ark::es2panda::ir {
class Literal;
class TypeNode;
class AnnotatedExpression;

class Expression : public TypedAstNode {
public:
    Expression() = delete;
    ~Expression() override = default;

    NO_COPY_OPERATOR(Expression);
    NO_MOVE_SEMANTIC(Expression);

    [[nodiscard]] bool IsGrouped() const noexcept
    {
        return grouped_;
    }

    void SetGrouped() noexcept
    {
        grouped_ = true;
    }

    [[nodiscard]] const Literal *AsLiteral() const
    {
        ASSERT(IsLiteral());
        return reinterpret_cast<const Literal *>(this);
    }

    [[nodiscard]] Literal *AsLiteral()
    {
        ASSERT(IsLiteral());
        return reinterpret_cast<Literal *>(this);
    }

    [[nodiscard]] virtual bool IsLiteral() const noexcept
    {
        return false;
    }

    [[nodiscard]] virtual bool IsTypeNode() const noexcept
    {
        return false;
    }

    [[nodiscard]] virtual bool IsAnnotatedExpression() const noexcept
    {
        return false;
    }

    [[nodiscard]] bool IsExpression() const noexcept override
    {
        return true;
    }

    [[nodiscard]] TypeNode *AsTypeNode()
    {
        ASSERT(IsTypeNode());
        return reinterpret_cast<TypeNode *>(this);
    }

    [[nodiscard]] const TypeNode *AsTypeNode() const
    {
        ASSERT(IsTypeNode());
        return reinterpret_cast<const TypeNode *>(this);
    }

    [[nodiscard]] AnnotatedExpression *AsAnnotatedExpression()
    {
        ASSERT(IsAnnotatedExpression());
        return reinterpret_cast<AnnotatedExpression *>(this);
    }

    [[nodiscard]] const AnnotatedExpression *AsAnnotatedExpression() const
    {
        ASSERT(IsAnnotatedExpression());
        return reinterpret_cast<const AnnotatedExpression *>(this);
    }

protected:
    explicit Expression(AstNodeType const type) : TypedAstNode(type) {}
    explicit Expression(AstNodeType const type, ModifierFlags const flags) : TypedAstNode(type, flags) {}

    Expression(Expression const &other) : TypedAstNode(static_cast<TypedAstNode const &>(other))
    {
        grouped_ = other.grouped_;
    }

private:
    bool grouped_ {};
};

class AnnotatedExpression : public Annotated<Expression> {
public:
    AnnotatedExpression() = delete;
    ~AnnotatedExpression() override = default;

    NO_COPY_SEMANTIC(AnnotatedExpression);
    NO_MOVE_SEMANTIC(AnnotatedExpression);

    [[nodiscard]] bool IsAnnotatedExpression() const noexcept override
    {
        return true;
    }

protected:
    explicit AnnotatedExpression(AstNodeType const type, TypeNode *const typeAnnotation)
        : Annotated<Expression>(type, typeAnnotation)
    {
    }
    explicit AnnotatedExpression(AstNodeType const type) : Annotated<Expression>(type) {}

    explicit AnnotatedExpression(AnnotatedExpression const &other, ArenaAllocator *allocator);
};

class MaybeOptionalExpression : public Expression {
public:
    MaybeOptionalExpression() = delete;
    ~MaybeOptionalExpression() override = default;

    NO_COPY_OPERATOR(MaybeOptionalExpression);
    NO_MOVE_SEMANTIC(MaybeOptionalExpression);

    [[nodiscard]] bool IsOptional() const noexcept
    {
        return optional_;
    }

    void ClearOptional() noexcept
    {
        optional_ = false;
    }

protected:
    explicit MaybeOptionalExpression(AstNodeType type, bool optional) : Expression(type), optional_(optional) {}
    explicit MaybeOptionalExpression(AstNodeType type, ModifierFlags flags, bool optional)
        : Expression(type, flags), optional_(optional)
    {
    }

    MaybeOptionalExpression(MaybeOptionalExpression const &other) : Expression(static_cast<Expression const &>(other))
    {
        optional_ = other.optional_;
    }

private:
    bool optional_;
};

}  // namespace ark::es2panda::ir

#endif /* ES2PANDA_IR_EXPRESSION_H */
