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

#ifndef ES2PANDA_IR_TS_INTERFACE_DECLARATION_H
#define ES2PANDA_IR_TS_INTERFACE_DECLARATION_H

#include "binder/scope.h"
#include "ir/statement.h"
#include "util/language.h"

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class Identifier;
class TSInterfaceBody;
class TSInterfaceHeritage;
class TSTypeParameterDeclaration;

class TSInterfaceDeclaration : public TypedStatement {
public:
    explicit TSInterfaceDeclaration(ArenaAllocator *allocator, binder::LocalScope *scope, Identifier *id,
                                    TSTypeParameterDeclaration *type_params, TSInterfaceBody *body,
                                    ArenaVector<TSInterfaceHeritage *> &&extends, bool is_static, Language lang)
        : TypedStatement(AstNodeType::TS_INTERFACE_DECLARATION),
          decorators_(allocator->Adapter()),
          scope_(scope),
          id_(id),
          type_params_(type_params),
          body_(body),
          extends_(std::move(extends)),
          is_static_(is_static),
          lang_(lang)
    {
        if (is_static_) {
            AddModifier(ir::ModifierFlags::STATIC);
        }
    }

    bool IsScopeBearer() const override
    {
        return true;
    }

    binder::LocalScope *Scope() const override
    {
        return scope_;
    }

    TSInterfaceBody *Body()
    {
        return body_;
    }

    const TSInterfaceBody *Body() const
    {
        return body_;
    }

    Identifier *Id()
    {
        return id_;
    }

    const Identifier *Id() const
    {
        return id_;
    }

    const util::StringView &InternalName() const
    {
        return internal_name_;
    }

    void SetInternalName(util::StringView internal_name)
    {
        internal_name_ = internal_name;
    }

    bool IsStatic() const
    {
        return is_static_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    TSTypeParameterDeclaration *TypeParams()
    {
        return type_params_;
    }

    ArenaVector<TSInterfaceHeritage *> &Extends()
    {
        return extends_;
    }

    const ArenaVector<TSInterfaceHeritage *> &Extends() const
    {
        return extends_;
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

    void TransformChildren(const NodeTransformer &cb) override;

    es2panda::Language Language() const
    {
        return lang_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;
    checker::Type *InferType(checker::TSChecker *checker, binder::Variable *binding_var) const;

private:
    ArenaVector<Decorator *> decorators_;
    binder::LocalScope *scope_;
    Identifier *id_;
    TSTypeParameterDeclaration *type_params_;
    TSInterfaceBody *body_;
    ArenaVector<TSInterfaceHeritage *> extends_;
    util::StringView internal_name_ {};
    bool is_static_;
    es2panda::Language lang_;
};
}  // namespace panda::es2panda::ir

#endif
