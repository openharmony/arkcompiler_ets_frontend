/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_H

#include "ir/astNode.h"

namespace panda::es2panda::ir {
class ClassElement;

class Statement : public AstNode {
public:
    bool IsStatement() const override
    {
        return true;
    }

protected:
    explicit Statement(AstNodeType type) : AstNode(type) {}
    explicit Statement(AstNodeType type, ModifierFlags flags) : AstNode(type, flags) {}
};

class TypedStatement : public Typed<Statement> {
protected:
    explicit TypedStatement(AstNodeType type) : Typed<Statement>(type) {};
    explicit TypedStatement(AstNodeType type, ModifierFlags flags) : Typed<Statement>(type, flags) {};

    inline static checker::Type *const CHECKED = reinterpret_cast<checker::Type *>(0x01);
};

class AnnotatedStatement : public Annotated<Statement> {
protected:
    explicit AnnotatedStatement(AstNodeType type, TypeNode *type_annotation)
        : Annotated<Statement>(type, type_annotation)
    {
    }

    explicit AnnotatedStatement(AstNodeType type) : Annotated<Statement>(type) {}
    explicit AnnotatedStatement(AstNodeType type, ModifierFlags flags) : Annotated<Statement>(type, flags) {}
};
}  // namespace panda::es2panda::ir

#endif
