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

#ifndef ES2PANDA_IR_EXPRESSION_IDENTIFIER_H
#define ES2PANDA_IR_EXPRESSION_IDENTIFIER_H

#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"
#include "plugins/ecmascript/es2panda/ir/validationInfo.h"

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
enum class IdentifierFlags : uint32_t {
    NONE = 0U,
    OPTIONAL = 1U << 0U,
    REFERENCE = 1U << 1U,
    TDZ = 1U << 2U,
    PRIVATE = 1U << 3U,
    GET = 1U << 4U,
    SET = 1U << 5U,
    IGNORE_BOX = 1U << 6U,
};

DEFINE_BITOPS(IdentifierFlags)

class Identifier : public AnnotatedExpression {
public:
    explicit Identifier(ArenaAllocator *allocator) : Identifier("", allocator) {}
    explicit Identifier(util::StringView name, ArenaAllocator *allocator)
        : AnnotatedExpression(AstNodeType::IDENTIFIER), name_(name), decorators_(allocator->Adapter())
    {
    }

    explicit Identifier(util::StringView name, TypeNode *type_annotation, ArenaAllocator *allocator)
        : AnnotatedExpression(AstNodeType::IDENTIFIER, type_annotation), name_(name), decorators_(allocator->Adapter())
    {
    }

    const util::StringView &Name() const
    {
        return name_;
    }

    util::StringView &Name()
    {
        return name_;
    }

    void SetName(const util::StringView &new_name)
    {
        name_ = new_name;
    }

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    bool IsOptional() const
    {
        return (flags_ & IdentifierFlags::OPTIONAL) != 0;
    }

    void SetOptional(bool optional)
    {
        if (optional) {
            flags_ |= IdentifierFlags::OPTIONAL;
        } else {
            flags_ &= ~IdentifierFlags::OPTIONAL;
        }
    }

    bool IsReference() const
    {
        return (flags_ & IdentifierFlags::REFERENCE) != 0;
    }

    void SetReference(bool is_reference = true)
    {
        if (is_reference) {
            flags_ |= IdentifierFlags::REFERENCE;
        } else {
            flags_ &= ~IdentifierFlags::REFERENCE;
        }
    }

    bool IsTdz() const
    {
        return (flags_ & IdentifierFlags::TDZ) != 0;
    }

    void SetTdz()
    {
        flags_ |= IdentifierFlags::TDZ;
    }

    void SetAccessor()
    {
        flags_ |= IdentifierFlags::GET;
    }

    bool IsAccessor() const
    {
        return (flags_ & IdentifierFlags::GET) != 0;
    }

    void SetMutator()
    {
        flags_ |= IdentifierFlags::SET;
    }

    bool IsMutator() const
    {
        return (flags_ & IdentifierFlags::SET) != 0;
    }

    bool IsPrivateIdent() const
    {
        return (flags_ & IdentifierFlags::PRIVATE) != 0;
    }

    void SetPrivate(bool is_private)
    {
        if (is_private) {
            flags_ |= IdentifierFlags::PRIVATE;
        } else {
            flags_ &= ~IdentifierFlags::PRIVATE;
        }
    }

    bool IsIgnoreBox() const
    {
        return (flags_ & IdentifierFlags::IGNORE_BOX) != 0;
    }

    void SetIgnoreBox()
    {
        flags_ |= IdentifierFlags::IGNORE_BOX;
    }

    binder::Variable *Variable() const
    {
        return variable_;
    }

    void SetVariable(binder::Variable *variable)
    {
        variable_ = variable;
    }

    binder::Variable *Variable()
    {
        return variable_;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    ValidationInfo ValidateExpression();

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    util::StringView name_;
    IdentifierFlags flags_ {IdentifierFlags::NONE};
    ArenaVector<Decorator *> decorators_;
    binder::Variable *variable_ {};
};
}  // namespace panda::es2panda::ir

#endif
