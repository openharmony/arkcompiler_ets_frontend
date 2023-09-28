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

#ifndef ES2PANDA_IR_TS_TYPE_ALIAS_DECLARATION_H
#define ES2PANDA_IR_TS_TYPE_ALIAS_DECLARATION_H

#include "plugins/ecmascript/es2panda/ir/statement.h"

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class Identifier;
class TSTypeParameterDeclaration;

class TSTypeAliasDeclaration : public AnnotatedStatement {
public:
    explicit TSTypeAliasDeclaration(ArenaAllocator *allocator, Identifier *id, TSTypeParameterDeclaration *type_params,
                                    TypeNode *type_annotation, bool declare)
        : AnnotatedStatement(AstNodeType::TS_TYPE_ALIAS_DECLARATION, type_annotation),
          decorators_(allocator->Adapter()),
          id_(id),
          type_params_(type_params),
          declare_(declare)
    {
    }

    explicit TSTypeAliasDeclaration(ArenaAllocator *allocator, Identifier *id)
        : AnnotatedStatement(AstNodeType::TS_TYPE_ALIAS_DECLARATION),
          decorators_(allocator->Adapter()),
          id_(id),
          type_params_(nullptr),
          declare_(false)
    {
    }

    Identifier *Id()
    {
        return id_;
    }

    const Identifier *Id() const
    {
        return id_;
    }

    const TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    bool Declare() const
    {
        return declare_;
    }

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    void AddTypeParameters(ir::TSTypeParameterDeclaration *type_params)
    {
        type_params_ = type_params;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    bool CanHaveDecorator([[maybe_unused]] bool in_ts) const override
    {
        return !in_ts;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    ArenaVector<Decorator *> decorators_;
    Identifier *id_;
    TSTypeParameterDeclaration *type_params_;
    bool declare_;
};
}  // namespace panda::es2panda::ir

#endif
