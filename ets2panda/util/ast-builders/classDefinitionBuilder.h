/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_INCLUDE_CLASS_DEFINITION_BUILDER
#define ES2PANDA_UTIL_INCLUDE_CLASS_DEFINITION_BUILDER

#include "ir/base/classDefinition.h"
#include "mem/arena_allocator.h"
#include "astBuilder.h"

namespace ark::es2panda::ir {

class ClassDefinitionBuilder : public AstBuilder {
public:
    explicit ClassDefinitionBuilder(ark::ArenaAllocator *allocator)
        : AstBuilder(allocator), body_(Allocator()->Adapter()), implements_(Allocator()->Adapter())
    {
    }

    ClassDefinitionBuilder &SetIdentifier(util::StringView id)
    {
        ident_ = AllocNode<ir::Identifier>(id, Allocator());
        return *this;
    }

    ClassDefinitionBuilder &SetConstructor(MethodDefinition *ctor)
    {
        ctor_ = ctor;
        return *this;
    }

    ClassDefinitionBuilder &SetSuperClass(Expression *superClass)
    {
        superClass_ = superClass;
        return *this;
    }

    ClassDefinitionBuilder &AddProperty(AstNode *property)
    {
        body_.push_back(property);
        return *this;
    }

    ClassDefinitionBuilder &SetParent(AstNode *const parent)
    {
        parent_ = parent;
        return *this;
    }

    ClassDefinitionBuilder &SetTSTypeParameterDeclaration(TSTypeParameterDeclaration *typeParams)
    {
        typeParams_ = typeParams;
        return *this;
    }

    ClassDefinitionBuilder &SetTSTypeParameterInstantiation(TSTypeParameterInstantiation *superTypeParams)
    {
        superTypeParams_ = superTypeParams;
        return *this;
    }

    ClassDefinitionBuilder &SetImplements(ArenaVector<TSClassImplements *> implements)
    {
        implements_ = std::move(implements);
        return *this;
    }

    ClassDefinitionBuilder &AddImplements(TSClassImplements *implement)
    {
        implements_.push_back(implement);
        return *this;
    }

    ClassDefinition *Build()
    {
        auto classDef = AllocNode<ClassDefinition>(util::StringView(), ident_, typeParams_, superTypeParams_,
                                                   std::move(implements_), ctor_, superClass_, std::move(body_),
                                                   ir::ClassDefinitionModifiers::CLASS_DECL, ir::ModifierFlags::NONE,
                                                   Language(Language::Id::ETS));
        classDef->SetParent(parent_);
        return classDef;
    }

private:
    util::StringView privateId_ {};
    Identifier *ident_ {};
    MethodDefinition *ctor_ {};
    Expression *superClass_ {};
    ArenaVector<AstNode *> body_;
    TSTypeParameterDeclaration *typeParams_ {};
    TSTypeParameterInstantiation *superTypeParams_ {};
    ArenaVector<TSClassImplements *> implements_;
    AstNode *parent_ {};
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_CLASS_DEFINITION_BUILDER