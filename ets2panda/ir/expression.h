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

#ifndef ES2PANDA_IR_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_H

#include "ir/astNode.h"

namespace panda::es2panda::ir {
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

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] virtual Expression *Clone([[maybe_unused]] ArenaAllocator *const allocator,
                                            [[maybe_unused]] AstNode *const parent = nullptr)
    {
        UNREACHABLE();
        return nullptr;
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

    NO_COPY_OPERATOR(AnnotatedExpression);
    NO_MOVE_SEMANTIC(AnnotatedExpression);

    [[nodiscard]] bool IsAnnotatedExpression() const noexcept override
    {
        return true;
    }

protected:
    explicit AnnotatedExpression(AstNodeType const type, TypeNode *const type_annotation)
        : Annotated<Expression>(type, type_annotation)
    {
    }
    explicit AnnotatedExpression(AstNodeType const type) : Annotated<Expression>(type) {}

    AnnotatedExpression(AnnotatedExpression const &other)
        : Annotated<Expression>(static_cast<Annotated<Expression> const &>(other))
    {
    }

    void CloneTypeAnnotation(ArenaAllocator *allocator);
};
}  // namespace panda::es2panda::ir

#endif /* ES2PANDA_IR_EXPRESSION_H */
