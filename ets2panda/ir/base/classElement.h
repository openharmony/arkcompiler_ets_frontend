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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_CLASS_ELEMENT_H
#define ES2PANDA_PARSER_INCLUDE_AST_CLASS_ELEMENT_H

#include "ir/statement.h"

namespace panda::es2panda::ir {
class Expression;

class ClassElement : public TypedStatement {
public:
    explicit ClassElement(AstNodeType element_type, Expression *key, Expression *value, ModifierFlags modifiers,
                          ArenaAllocator *allocator, bool is_computed)
        : TypedStatement(element_type, modifiers),
          key_(key),
          value_(value),
          decorators_(allocator->Adapter()),
          is_computed_(is_computed)
    {
    }

    Identifier *Id();
    const Identifier *Id() const;

    Expression *Key()
    {
        return key_;
    }

    const Expression *Key() const
    {
        return key_;
    }

    Expression *Value()
    {
        return value_;
    }

    const Expression *Value() const
    {
        return value_;
    }

    bool IsPrivateElement() const;

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    bool IsComputed() const
    {
        return is_computed_;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    virtual PrivateFieldKind ToPrivateFieldKind(bool is_static) const = 0;

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Expression *key_;
    Expression *value_;
    ArenaVector<Decorator *> decorators_;
    bool is_computed_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};
}  // namespace panda::es2panda::ir

#endif
