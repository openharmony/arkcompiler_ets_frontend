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

#ifndef ES2PANDA_IR_TS_ENUM_DECLARATION_H
#define ES2PANDA_IR_TS_ENUM_DECLARATION_H

#include "varbinder/scope.h"
#include "ir/statement.h"
#include "varbinder/enumMemberResult.h"

namespace ark::es2panda::varbinder {
class EnumVariable;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::ir {
class Identifier;
class TSEnumMember;

class TSEnumDeclaration : public TypedStatement {
public:
    explicit TSEnumDeclaration(ArenaAllocator *allocator, Identifier *key, ArenaVector<AstNode *> &&members,
                               bool isConst, bool isStatic = false, bool isDeclare = false)
        : TypedStatement(AstNodeType::TS_ENUM_DECLARATION),
          decorators_(allocator->Adapter()),
          key_(key),
          members_(std::move(members)),
          isConst_(isConst),
          isDeclare_(isDeclare)
    {
        if (isStatic) {
            AddModifier(ModifierFlags::STATIC);
        }
        if (isDeclare) {
            AddModifier(ModifierFlags::DECLARE);
        }
    }

    [[nodiscard]] bool IsScopeBearer() const noexcept override
    {
        return true;
    }

    [[nodiscard]] varbinder::LocalScope *Scope() const noexcept override
    {
        return scope_;
    }

    void SetScope(varbinder::LocalScope *scope)
    {
        ASSERT(scope_ == nullptr);
        scope_ = scope;
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
        return internalName_;
    }

    void SetInternalName(util::StringView internalName)
    {
        internalName_ = internalName;
    }

    bool IsConst() const
    {
        return isConst_;
    }

    bool IsDeclare() const
    {
        return isDeclare_;
    }

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    const ArenaVector<Decorator *> *DecoratorsPtr() const override
    {
        return &Decorators();
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    bool CanHaveDecorator([[maybe_unused]] bool inTs) const override
    {
        return !inTs;
    }

    static varbinder::EnumMemberResult EvaluateEnumMember(checker::TSChecker *checker, varbinder::EnumVariable *enumVar,
                                                          const ir::AstNode *expr);
    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    varbinder::LocalScope *scope_ {nullptr};
    ArenaVector<ir::Decorator *> decorators_;
    Identifier *key_;
    ArenaVector<AstNode *> members_;
    util::StringView internalName_;
    bool isConst_;
    bool isDeclare_;
};
}  // namespace ark::es2panda::ir

#endif
