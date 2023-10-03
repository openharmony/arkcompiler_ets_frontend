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

#ifndef ES2PANDA_IR_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_H

#include "ir/astNode.h"

namespace panda::es2panda::ir {
class Literal;
class TypeNode;
class AnnotatedExpression;

class Expression : public TypedAstNode {
public:
    bool IsGrouped() const
    {
        return grouped_;
    }

    void SetGrouped()
    {
        grouped_ = true;
    }

    const Literal *AsLiteral() const
    {
        ASSERT(IsLiteral());
        return reinterpret_cast<const Literal *>(this);
    }

    Literal *AsLiteral()
    {
        ASSERT(IsLiteral());
        return reinterpret_cast<Literal *>(this);
    }

    virtual bool IsLiteral() const
    {
        return false;
    }

    virtual bool IsTypeNode() const
    {
        return false;
    }

    virtual bool IsAnnotatedExpression() const
    {
        return false;
    }

    bool IsExpression() const override
    {
        return true;
    }

    TypeNode *AsTypeNode()
    {
        ASSERT(IsTypeNode());
        return reinterpret_cast<TypeNode *>(this);
    }

    const TypeNode *AsTypeNode() const
    {
        ASSERT(IsTypeNode());
        return reinterpret_cast<const TypeNode *>(this);
    }

    AnnotatedExpression *AsAnnotatedExpression()
    {
        ASSERT(IsAnnotatedExpression());
        return reinterpret_cast<AnnotatedExpression *>(this);
    }

    const AnnotatedExpression *AsAnnotatedExpression() const
    {
        ASSERT(IsAnnotatedExpression());
        return reinterpret_cast<const AnnotatedExpression *>(this);
    }

protected:
    explicit Expression(AstNodeType type) : TypedAstNode(type) {}
    explicit Expression(AstNodeType type, ModifierFlags flags) : TypedAstNode(type, flags) {}

private:
    bool grouped_ {};
};

class AnnotatedExpression : public Annotated<Expression> {
protected:
    explicit AnnotatedExpression(AstNodeType type, TypeNode *type_annotation)
        : Annotated<Expression>(type, type_annotation)
    {
    }
    explicit AnnotatedExpression(AstNodeType type) : Annotated<Expression>(type) {}

    bool IsAnnotatedExpression() const override
    {
        return true;
    }
};
}  // namespace panda::es2panda::ir

#endif /* ES2PANDA_IR_EXPRESSION_H */
