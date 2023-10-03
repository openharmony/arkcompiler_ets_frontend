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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_CLASS_DEFINITION_H
#define ES2PANDA_PARSER_INCLUDE_AST_CLASS_DEFINITION_H

#include "ir/astNode.h"
#include "binder/variable.h"
#include "util/bitset.h"

namespace panda::es2panda::binder {
class LocalScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class ClassElement;
class Identifier;
class MethodDefinition;
class TSTypeParameterDeclaration;
class TSTypeParameterInstantiation;
class TSClassImplements;
class TSIndexSignature;

enum class ClassDefinitionModifiers : uint32_t {
    NONE = 0,
    DECLARATION = 1U << 0U,
    ID_REQUIRED = 1U << 1U,
    GLOBAL = 1U << 2U,
    HAS_SUPER = 1U << 3U,
    SET_CTOR_ID = 1U << 4U,
    EXTERN = 1U << 5U,
    ANONYMOUS = 1U << 6U,
    GLOBAL_INITIALIZED = 1U << 7U,
    CLASS_DECL = 1U << 8U,
    INNER = 1U << 9U,
    DECLARATION_ID_REQUIRED = DECLARATION | ID_REQUIRED
};

DEFINE_BITOPS(ClassDefinitionModifiers)

class ClassDefinition : public TypedAstNode {
public:
    explicit ClassDefinition(binder::LocalScope *scope, const util::StringView &private_id, Identifier *ident,
                             TSTypeParameterDeclaration *type_params, TSTypeParameterInstantiation *super_type_params,
                             ArenaVector<TSClassImplements *> &&implements, MethodDefinition *ctor,
                             Expression *super_class, ArenaVector<AstNode *> &&body, ClassDefinitionModifiers modifiers,
                             ModifierFlags flags)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION, flags),
          scope_(scope),
          private_id_(private_id),
          ident_(ident),
          type_params_(type_params),
          super_type_params_(super_type_params),
          implements_(std::move(implements)),
          ctor_(ctor),
          super_class_(super_class),
          body_(std::move(body)),
          modifiers_(modifiers)
    {
    }

    explicit ClassDefinition(ArenaAllocator *allocator, binder::LocalScope *scope, Identifier *ident,
                             ArenaVector<AstNode *> &&body, ClassDefinitionModifiers modifiers)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION),
          scope_(scope),
          ident_(ident),
          implements_(allocator->Adapter()),
          body_(std::move(body)),
          modifiers_(modifiers)
    {
    }

    explicit ClassDefinition(ArenaAllocator *allocator, binder::LocalScope *scope, Identifier *ident,
                             ClassDefinitionModifiers modifiers, ModifierFlags flags)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION, flags),
          scope_(scope),
          ident_(ident),
          implements_(allocator->Adapter()),
          body_(allocator->Adapter()),
          modifiers_(modifiers)
    {
    }

    binder::LocalScope *Scope() const
    {
        return scope_;
    }

    const Identifier *Ident() const
    {
        return ident_;
    }

    Identifier *Ident()
    {
        return ident_;
    }

    void SetIdent(ir::Identifier *ident)
    {
        ident_ = ident;
    }

    const util::StringView &PrivateId() const
    {
        return private_id_;
    }

    const util::StringView &InternalName() const
    {
        return private_id_;
    }

    void SetInternalName(util::StringView internal_name)
    {
        private_id_ = internal_name;
    }

    Expression *Super()
    {
        return super_class_;
    }

    const Expression *Super() const
    {
        return super_class_;
    }

    bool IsGlobal() const
    {
        return (modifiers_ & ClassDefinitionModifiers::GLOBAL) != 0;
    }

    bool IsExtern() const
    {
        return (modifiers_ & ClassDefinitionModifiers::EXTERN) != 0;
    }

    bool IsInner() const
    {
        return (modifiers_ & ClassDefinitionModifiers::INNER) != 0;
    }

    bool IsGlobalInitialized() const
    {
        return (modifiers_ & ClassDefinitionModifiers::GLOBAL_INITIALIZED) != 0;
    }

    void SetGlobalInitialized()
    {
        modifiers_ |= ClassDefinitionModifiers::GLOBAL_INITIALIZED;
    }

    void SetInnerModifier()
    {
        modifiers_ |= ClassDefinitionModifiers::INNER;
    }

    ClassDefinitionModifiers Modifiers() const
    {
        return modifiers_;
    }

    void AddProperties(ArenaVector<AstNode *> &&body)
    {
        for (auto *prop : body) {
            prop->SetParent(this);
        }

        body_.insert(body_.end(), body.begin(), body.end());
    }

    ArenaVector<AstNode *> &Body()
    {
        return body_;
    }

    const ArenaVector<AstNode *> &Body() const
    {
        return body_;
    }

    MethodDefinition *Ctor()
    {
        return ctor_;
    }

    ArenaVector<ir::TSClassImplements *> &Implements()
    {
        return implements_;
    }

    const ArenaVector<ir::TSClassImplements *> &Implements() const
    {
        return implements_;
    }

    const ir::TSTypeParameterDeclaration *TypeParams() const
    {
        return type_params_;
    }

    ir::TSTypeParameterDeclaration *TypeParams()
    {
        return type_params_;
    }

    const FunctionExpression *Ctor() const;
    bool HasPrivateMethod() const;
    bool HasComputedInstanceField() const;
    bool HasMatchingPrivateKey(const util::StringView &name) const;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    compiler::VReg CompileHeritageClause(compiler::PandaGen *pg) const;
    void InitializeClassName(compiler::PandaGen *pg) const;
    void CompileMissingProperties(compiler::PandaGen *pg, const util::BitSet &compiled, compiler::VReg class_reg) const;
    void CompileStaticFieldInitializers(compiler::PandaGen *pg, compiler::VReg class_reg,
                                        const std::vector<compiler::VReg> &static_computed_field_keys) const;

    binder::LocalScope *scope_;
    util::StringView private_id_ {};
    Identifier *ident_ {};
    TSTypeParameterDeclaration *type_params_ {};
    TSTypeParameterInstantiation *super_type_params_ {};
    ArenaVector<TSClassImplements *> implements_;
    MethodDefinition *ctor_ {};
    Expression *super_class_ {};
    ArenaVector<AstNode *> body_;
    ClassDefinitionModifiers modifiers_;
};
}  // namespace panda::es2panda::ir

#endif
