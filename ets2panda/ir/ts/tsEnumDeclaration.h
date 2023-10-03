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

#ifndef ES2PANDA_IR_TS_ENUM_DECLARATION_H
#define ES2PANDA_IR_TS_ENUM_DECLARATION_H

#include "ir/statement.h"
#include "binder/enumMemberResult.h"

namespace panda::es2panda::binder {
class LocalScope;
class EnumVariable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class Identifier;
class TSEnumMember;

class TSEnumDeclaration : public TypedStatement {
public:
    explicit TSEnumDeclaration(ArenaAllocator *allocator, binder::LocalScope *scope, Identifier *key,
                               ArenaVector<AstNode *> &&members, bool is_const, bool is_static = false)
        : TypedStatement(AstNodeType::TS_ENUM_DECLARATION),
          scope_(scope),
          decorators_(allocator->Adapter()),
          key_(key),
          members_(std::move(members)),
          is_const_(is_const)
    {
        if (is_static) {
            AddModifier(ModifierFlags::STATIC);
        }
    }

    binder::LocalScope *Scope() const
    {
        return scope_;
    }

    const Identifier *Key() const
    {
        return key_;
    }

    Identifier *Key()
    {
        return key_;
    }

    const ArenaVector<AstNode *> &Members() const
    {
        return members_;
    }

    const util::StringView &InternalName() const
    {
        return internal_name_;
    }

    void SetInternalName(util::StringView internal_name)
    {
        internal_name_ = internal_name;
    }

    bool IsConst() const
    {
        return is_const_;
    }

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    bool CanHaveDecorator([[maybe_unused]] bool in_ts) const override
    {
        return !in_ts;
    }

    static binder::EnumMemberResult EvaluateEnumMember(checker::TSChecker *checker, binder::EnumVariable *enum_var,
                                                       const ir::AstNode *expr);
    checker::Type *InferType(checker::TSChecker *checker, bool is_const) const;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::LocalScope *scope_;
    ArenaVector<ir::Decorator *> decorators_;
    Identifier *key_;
    ArenaVector<AstNode *> members_;
    util::StringView internal_name_;
    bool is_const_;
};
}  // namespace panda::es2panda::ir

#endif
