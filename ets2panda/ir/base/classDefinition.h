/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "varbinder/scope.h"
#include "varbinder/variable.h"
#include "ir/astNode.h"
#include "util/bitset.h"
#include "util/language.h"

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
    FROM_EXTERNAL = 1U << 10U,
    DECLARATION_ID_REQUIRED = DECLARATION | ID_REQUIRED
};

DEFINE_BITOPS(ClassDefinitionModifiers)

class ClassDefinition : public TypedAstNode {
public:
    ClassDefinition() = delete;
    ~ClassDefinition() override = default;

    NO_COPY_SEMANTIC(ClassDefinition);
    NO_MOVE_SEMANTIC(ClassDefinition);

    explicit ClassDefinition(const util::StringView &private_id, Identifier *ident,
                             TSTypeParameterDeclaration *type_params, TSTypeParameterInstantiation *super_type_params,
                             ArenaVector<TSClassImplements *> &&implements, MethodDefinition *ctor,
                             Expression *super_class, ArenaVector<AstNode *> &&body, ClassDefinitionModifiers modifiers,
                             ModifierFlags flags, Language lang)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION, flags),
          private_id_(private_id),
          ident_(ident),
          type_params_(type_params),
          super_type_params_(super_type_params),
          implements_(std::move(implements)),
          ctor_(ctor),
          super_class_(super_class),
          body_(std::move(body)),
          modifiers_(modifiers),
          lang_(lang)
    {
    }

    explicit ClassDefinition(ArenaAllocator *allocator, Identifier *ident, ArenaVector<AstNode *> &&body,
                             ClassDefinitionModifiers modifiers, Language lang)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION),
          ident_(ident),
          implements_(allocator->Adapter()),
          body_(std::move(body)),
          modifiers_(modifiers),
          lang_(lang)
    {
    }

    explicit ClassDefinition(ArenaAllocator *allocator, Identifier *ident, ClassDefinitionModifiers modifiers,
                             ModifierFlags flags, Language lang)
        : TypedAstNode(AstNodeType::CLASS_DEFINITION, flags),
          ident_(ident),
          implements_(allocator->Adapter()),
          body_(allocator->Adapter()),
          modifiers_(modifiers),
          lang_(lang)
    {
    }

    bool IsScopeBearer() const override
    {
        return true;
    }

    varbinder::LocalScope *Scope() const override
    {
        return scope_;
    }

    void SetScope(varbinder::LocalScope *scope)
    {
        scope_ = scope;
    }

    [[nodiscard]] const Identifier *Ident() const noexcept
    {
        return ident_;
    }

    [[nodiscard]] Identifier *Ident() noexcept
    {
        return ident_;
    }

    void SetIdent(ir::Identifier *ident) noexcept
    {
        ident_ = ident;
    }

    [[nodiscard]] const util::StringView &PrivateId() const noexcept
    {
        return private_id_;
    }

    [[nodiscard]] const util::StringView &InternalName() const noexcept
    {
        return private_id_;
    }

    void SetInternalName(util::StringView internal_name) noexcept
    {
        private_id_ = internal_name;
    }

    [[nodiscard]] Expression *Super() noexcept
    {
        return super_class_;
    }

    [[nodiscard]] const Expression *Super() const noexcept
    {
        return super_class_;
    }

    void SetSuper(Expression *super_class)
    {
        super_class_ = super_class;
    }

    [[nodiscard]] bool IsGlobal() const noexcept
    {
        return (modifiers_ & ClassDefinitionModifiers::GLOBAL) != 0;
    }

    [[nodiscard]] bool IsExtern() const noexcept
    {
        return (modifiers_ & ClassDefinitionModifiers::EXTERN) != 0;
    }

    [[nodiscard]] bool IsFromExternal() const noexcept
    {
        return (modifiers_ & ClassDefinitionModifiers::FROM_EXTERNAL) != 0;
    }
    [[nodiscard]] bool IsInner() const noexcept
    {
        return (modifiers_ & ClassDefinitionModifiers::INNER) != 0;
    }

    [[nodiscard]] bool IsGlobalInitialized() const noexcept
    {
        return (modifiers_ & ClassDefinitionModifiers::GLOBAL_INITIALIZED) != 0;
    }

    [[nodiscard]] es2panda::Language Language() const noexcept
    {
        return lang_;
    }

    void SetGlobalInitialized() noexcept
    {
        modifiers_ |= ClassDefinitionModifiers::GLOBAL_INITIALIZED;
    }

    void SetInnerModifier() noexcept
    {
        modifiers_ |= ClassDefinitionModifiers::INNER;
    }

    [[nodiscard]] ClassDefinitionModifiers Modifiers() const noexcept
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

    [[nodiscard]] ArenaVector<AstNode *> &Body() noexcept
    {
        return body_;
    }

    [[nodiscard]] const ArenaVector<AstNode *> &Body() const noexcept
    {
        return body_;
    }

    [[nodiscard]] MethodDefinition *Ctor() noexcept
    {
        return ctor_;
    }

    void SetCtor(MethodDefinition *ctor)
    {
        ctor_ = ctor;
    }

    [[nodiscard]] ArenaVector<ir::TSClassImplements *> &Implements() noexcept
    {
        return implements_;
    }

    [[nodiscard]] const ArenaVector<ir::TSClassImplements *> &Implements() const noexcept
    {
        return implements_;
    }

    [[nodiscard]] const ir::TSTypeParameterDeclaration *TypeParams() const noexcept
    {
        return type_params_;
    }

    [[nodiscard]] ir::TSTypeParameterDeclaration *TypeParams() noexcept
    {
        return type_params_;
    }

    void SetTypeParams(ir::TSTypeParameterDeclaration *type_params)
    {
        type_params_ = type_params;
    }

    const TSTypeParameterInstantiation *SuperTypeParams() const
    {
        return super_type_params_;
    }

    TSTypeParameterInstantiation *SuperTypeParams()
    {
        return super_type_params_;
    }

    const FunctionExpression *Ctor() const;
    bool HasPrivateMethod() const;
    bool HasComputedInstanceField() const;
    bool HasMatchingPrivateKey(const util::StringView &name) const;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;

    void Dump(ir::AstDumper *dumper) const override;

    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    void CompileStaticFieldInitializers(compiler::PandaGen *pg, compiler::VReg class_reg,
                                        const std::vector<compiler::VReg> &static_computed_field_keys) const;

    varbinder::LocalScope *scope_ {nullptr};
    util::StringView private_id_ {};
    Identifier *ident_ {};
    TSTypeParameterDeclaration *type_params_ {};
    TSTypeParameterInstantiation *super_type_params_ {};
    ArenaVector<TSClassImplements *> implements_;
    MethodDefinition *ctor_ {};
    Expression *super_class_ {};
    ArenaVector<AstNode *> body_;
    ClassDefinitionModifiers modifiers_;
    es2panda::Language lang_;
};
}  // namespace panda::es2panda::ir

#endif
