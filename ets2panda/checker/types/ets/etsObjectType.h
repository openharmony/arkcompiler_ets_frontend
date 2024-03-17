/*
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_OBJECT_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_OBJECT_TYPE_H

#include "checker/types/type.h"
#include "checker/types/signature.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "varbinder/scope.h"
#include "ir/base/classDefinition.h"

namespace ark::es2panda::checker {

enum class ETSObjectFlags : uint32_t {
    NO_OPTS = 0U,
    CLASS = 1U << 0U,
    INTERFACE = 1U << 1U,
    INSTANCE = 1U << 2U,
    ABSTRACT = 1U << 3U,
    GLOBAL = 1U << 4U,
    ENUM = 1U << 5U,
    FUNCTIONAL = 1U << 6U,
    RESOLVED_INTERFACES = 1U << 7U,
    RESOLVED_SUPER = 1U << 8U,
    RESOLVED_TYPE_PARAMS = 1U << 9U,
    CHECKED_COMPATIBLE_ABSTRACTS = 1U << 10U,
    STRING = 1U << 11U,
    INCOMPLETE_INSTANTIATION = 1U << 12U,
    INNER = 1U << 13U,
    DYNAMIC = 1U << 14U,
    ASYNC_FUNC_RETURN_TYPE = 1U << 15U,
    CHECKED_INVOKE_LEGITIMACY = 1U << 16U,

    BUILTIN_BIGINT = 1U << 22U,
    BUILTIN_STRING = 1U << 23U,
    BUILTIN_BOOLEAN = 1U << 24U,
    BUILTIN_BYTE = 1U << 25U,
    BUILTIN_CHAR = 1U << 26U,
    BUILTIN_SHORT = 1U << 27U,
    BUILTIN_INT = 1U << 28U,
    BUILTIN_LONG = 1U << 29U,
    BUILTIN_FLOAT = 1U << 30U,
    BUILTIN_DOUBLE = 1U << 31U,

    UNBOXABLE_TYPE = BUILTIN_BOOLEAN | BUILTIN_BYTE | BUILTIN_CHAR | BUILTIN_SHORT | BUILTIN_INT | BUILTIN_LONG |
                     BUILTIN_FLOAT | BUILTIN_DOUBLE,
    BUILTIN_TYPE = BUILTIN_STRING | BUILTIN_BIGINT | UNBOXABLE_TYPE,
    VALID_SWITCH_TYPE =
        BUILTIN_BYTE | BUILTIN_CHAR | BUILTIN_SHORT | BUILTIN_INT | BUILTIN_LONG | BUILTIN_STRING | ENUM,
    GLOBAL_CLASS = CLASS | GLOBAL,
    FUNCTIONAL_INTERFACE = INTERFACE | ABSTRACT | FUNCTIONAL,
    RESOLVED_HEADER = RESOLVED_INTERFACES | RESOLVED_SUPER | RESOLVED_TYPE_PARAMS,
};

DEFINE_BITOPS(ETSObjectFlags)

// NOTE: Do not change the order of the first 7 flags (including NO_OPTS)!
// Because ETSChecker::ValidateResolvedProperty relies on the order of the flags.
enum class PropertySearchFlags : uint32_t {
    NO_OPTS = 0,
    SEARCH_INSTANCE_METHOD = 1U << 0U,
    SEARCH_INSTANCE_FIELD = 1U << 1U,
    SEARCH_INSTANCE_DECL = 1U << 2U,
    SEARCH_STATIC_METHOD = 1U << 3U,
    SEARCH_STATIC_FIELD = 1U << 4U,
    SEARCH_STATIC_DECL = 1U << 5U,

    SEARCH_IN_BASE = 1U << 6U,
    SEARCH_IN_INTERFACES = 1U << 7U,
    IGNORE_ABSTRACT = 1U << 8U,
    ALLOW_FUNCTIONAL_INTERFACE = 1U << 9U,
    DISALLOW_SYNTHETIC_METHOD_CREATION = 1U << 10U,
    IS_FUNCTIONAL = 1U << 11U,
    IS_SETTER = 1U << 12U,
    IS_GETTER = 1U << 13U,

    SEARCH_INSTANCE = SEARCH_INSTANCE_FIELD | SEARCH_INSTANCE_METHOD | SEARCH_INSTANCE_DECL,
    SEARCH_STATIC = SEARCH_STATIC_FIELD | SEARCH_STATIC_METHOD | SEARCH_STATIC_DECL,

    SEARCH_METHOD = SEARCH_INSTANCE_METHOD | SEARCH_STATIC_METHOD,
    SEARCH_FIELD = SEARCH_INSTANCE_FIELD | SEARCH_STATIC_FIELD,
    SEARCH_DECL = SEARCH_INSTANCE_DECL | SEARCH_STATIC_DECL,
    SEARCH_ALL = SEARCH_METHOD | SEARCH_FIELD | SEARCH_DECL,
};

DEFINE_BITOPS(PropertySearchFlags)

enum class PropertyType {
    INSTANCE_METHOD,
    INSTANCE_FIELD,
    INSTANCE_DECL,
    STATIC_METHOD,
    STATIC_FIELD,
    STATIC_DECL,
    COUNT,
};

/* Invoke method name in functional interfaces */
constexpr char const *FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME = "invoke0";

class ETSObjectType : public Type {
public:
    using PropertyMap = ArenaUnorderedMap<util::StringView, varbinder::LocalVariable *>;
    using InstantiationMap = ArenaUnorderedMap<util::StringView, ETSObjectType *>;
    using PropertyTraverser = std::function<void(const varbinder::LocalVariable *)>;
    using PropertyHolder = std::array<PropertyMap, static_cast<size_t>(PropertyType::COUNT)>;

    explicit ETSObjectType(ArenaAllocator *allocator) : ETSObjectType(allocator, ETSObjectFlags::NO_OPTS) {}

    explicit ETSObjectType(ArenaAllocator *allocator, ETSObjectFlags flags)
        : ETSObjectType(allocator, "", "", nullptr, flags, nullptr)
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, ETSObjectFlags flags, TypeRelation *relation)
        : ETSObjectType(allocator, "", "", nullptr, flags, relation)
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           ir::AstNode *declNode, ETSObjectFlags flags)
        : ETSObjectType(allocator, name, assemblerName, declNode, flags, nullptr,
                        std::make_index_sequence<static_cast<size_t>(PropertyType::COUNT)> {})
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           ir::AstNode *declNode, ETSObjectFlags flags, TypeRelation *relation)
        : ETSObjectType(allocator, name, assemblerName, declNode, flags, relation,
                        std::make_index_sequence<static_cast<size_t>(PropertyType::COUNT)> {})
    {
    }

    void AddConstructSignature(Signature *signature)
    {
        constructSignatures_.push_back(signature);
        propertiesInstantiated_ = true;
    }

    void AddConstructSignature(const ArenaVector<Signature *> &signatures) const
    {
        constructSignatures_.insert(constructSignatures_.end(), signatures.begin(), signatures.end());
        propertiesInstantiated_ = true;
    }

    void AddInterface(ETSObjectType *interface)
    {
        if (std::find(interfaces_.begin(), interfaces_.end(), interface) == interfaces_.end()) {
            interfaces_.push_back(interface);
        }
    }

    void SetSuperType(ETSObjectType *super)
    {
        superType_ = super;
    }

    void SetTypeArguments(ArenaVector<Type *> &&typeArgs)
    {
        typeArguments_ = std::move(typeArgs);
    }

    void SetEnclosingType(ETSObjectType *enclosingType)
    {
        enclosingType_ = enclosingType;
    }

    void SetRelation(TypeRelation *relation)
    {
        relation_ = relation;
    }

    TypeRelation *GetRelation() const
    {
        return relation_;
    }

    PropertyMap InstanceMethods() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::INSTANCE_METHOD)];
    }

    PropertyMap InstanceFields() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::INSTANCE_FIELD)];
    }

    PropertyMap InstanceDecls() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::INSTANCE_DECL)];
    }

    PropertyMap StaticMethods() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::STATIC_METHOD)];
    }

    PropertyMap StaticFields() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::STATIC_FIELD)];
    }

    PropertyMap StaticDecls() const
    {
        EnsurePropertiesInstantiated();
        return properties_[static_cast<size_t>(PropertyType::STATIC_DECL)];
    }

    const ArenaVector<Type *> &TypeArguments() const
    {
        return typeArguments_;
    }

    ArenaVector<Type *> &TypeArguments()
    {
        return typeArguments_;
    }

    const ArenaVector<Signature *> &ConstructSignatures() const
    {
        EnsurePropertiesInstantiated();
        return constructSignatures_;
    }

    ArenaVector<Signature *> &ConstructSignatures()
    {
        EnsurePropertiesInstantiated();
        return constructSignatures_;
    }

    const ArenaVector<ETSObjectType *> &Interfaces() const
    {
        return interfaces_;
    }

    ArenaVector<ETSObjectType *> &Interfaces()
    {
        return interfaces_;
    }

    ir::AstNode *GetDeclNode() const
    {
        return declNode_;
    }

    const ETSObjectType *SuperType() const
    {
        return superType_;
    }

    ETSObjectType *SuperType()
    {
        return superType_;
    }

    const ETSObjectType *EnclosingType() const
    {
        return enclosingType_;
    }

    ETSObjectType *EnclosingType()
    {
        return enclosingType_;
    }

    ETSObjectType *OutermostClass()
    {
        auto *iter = enclosingType_;

        while (iter != nullptr && iter->EnclosingType() != nullptr) {
            iter = iter->EnclosingType();
        }

        return iter;
    }

    void SetBaseType(ETSObjectType *baseType)
    {
        baseType_ = baseType;
    }

    ETSObjectType *GetBaseType() noexcept
    {
        return baseType_;
    }

    const ETSObjectType *GetBaseType() const noexcept
    {
        return baseType_;
    }

    ETSObjectType const *GetConstOriginalBaseType() const noexcept;

    ETSObjectType *GetOriginalBaseType() const noexcept
    {
        return const_cast<ETSObjectType *>(GetConstOriginalBaseType());
    }

    bool IsGlobalETSObjectType() const noexcept
    {
        return superType_ == nullptr;
    }

    bool IsPropertyInherited(const varbinder::Variable *var)
    {
        if (var->HasFlag(varbinder::VariableFlags::PRIVATE)) {
            return GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) ==
                   var;
        }

        if (var->HasFlag(varbinder::VariableFlags::PROTECTED)) {
            return (GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) ==
                    var) ||
                   this->IsPropertyOfAscendant(var);
        }

        return true;
    }

    bool IsPropertyOfAscendant(const varbinder::Variable *var) const
    {
        if (this->SuperType() == nullptr) {
            return false;
        }

        if (this->SuperType()->GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD |
                                                            PropertySearchFlags::SEARCH_DECL) == var) {
            return true;
        }

        return this->SuperType()->IsPropertyOfAscendant(var);
    }

    bool IsSignatureInherited(Signature *signature)
    {
        if (signature->HasSignatureFlag(SignatureFlags::PRIVATE)) {
            return signature->Owner() == this;
        }

        if (signature->HasSignatureFlag(SignatureFlags::PROTECTED)) {
            return signature->Owner() == this || this->IsDescendantOf(signature->Owner());
        }

        return true;
    }

    bool IsDescendantOf(const ETSObjectType *ascendant) const
    {
        if (this->SuperType() == nullptr) {
            return false;
        }

        if (this->SuperType() == ascendant) {
            return true;
        }

        return this->SuperType()->IsDescendantOf(ascendant);
    }

    const util::StringView &Name() const
    {
        return name_;
    }

    const util::StringView &AssemblerName() const
    {
        return assemblerName_;
    }

    void SetName(const util::StringView &newName)
    {
        name_ = newName;
    }

    void SetAssemblerName(const util::StringView &newName)
    {
        assemblerName_ = newName;
    }

    ETSObjectFlags ObjectFlags() const
    {
        return flags_;
    }

    void AddObjectFlag(ETSObjectFlags flag)
    {
        flags_ |= flag;
    }

    void RemoveObjectFlag(ETSObjectFlags flag)
    {
        flags_ &= ~flag;
    }

    bool HasObjectFlag(ETSObjectFlags flag) const
    {
        return (flags_ & flag) != 0;
    }

    ETSFunctionType *GetFunctionalInterfaceInvokeType() const
    {
        ASSERT(HasObjectFlag(ETSObjectFlags::FUNCTIONAL));
        auto *invoke = GetOwnProperty<PropertyType::INSTANCE_METHOD>(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME);
        ASSERT(invoke && invoke->TsType() && invoke->TsType()->IsETSFunctionType());
        return invoke->TsType()->AsETSFunctionType();
    }

    ETSObjectFlags BuiltInKind() const
    {
        return static_cast<checker::ETSObjectFlags>(flags_ & ETSObjectFlags::BUILTIN_TYPE);
    }

    ETSObjectType *GetInstantiatedType(util::StringView hash)
    {
        auto found = instantiationMap_.find(hash);
        if (found != instantiationMap_.end()) {
            return found->second;
        }

        return nullptr;
    }

    varbinder::Scope *GetTypeArgumentScope() const
    {
        auto *typeParams = GetTypeParams();
        if (typeParams == nullptr) {
            return nullptr;
        }
        return typeParams->Scope();
    }

    InstantiationMap &GetInstantiationMap()
    {
        return instantiationMap_;
    }

    template <PropertyType TYPE>
    varbinder::LocalVariable *GetOwnProperty(const util::StringView &name) const
    {
        EnsurePropertiesInstantiated();
        auto found = properties_[static_cast<size_t>(TYPE)].find(name);
        if (found != properties_[static_cast<size_t>(TYPE)].end()) {
            return found->second;
        }
        return nullptr;
    }

    template <PropertyType TYPE>
    void AddProperty(varbinder::LocalVariable *prop) const
    {
        properties_[static_cast<size_t>(TYPE)].emplace(prop->Name(), prop);
        propertiesInstantiated_ = true;
    }

    [[nodiscard]] bool IsGeneric() const noexcept
    {
        return !typeArguments_.empty();
    }

    std::vector<const varbinder::LocalVariable *> ForeignProperties() const;
    varbinder::LocalVariable *GetProperty(const util::StringView &name, PropertySearchFlags flags) const;
    std::vector<varbinder::LocalVariable *> GetAllProperties() const;
    void CreatePropertyMap(ArenaAllocator *allocator);
    varbinder::LocalVariable *CopyProperty(varbinder::LocalVariable *prop, ArenaAllocator *allocator,
                                           TypeRelation *relation, GlobalTypesHolder *globalTypes);
    std::vector<varbinder::LocalVariable *> Methods() const;
    std::vector<varbinder::LocalVariable *> Fields() const;
    varbinder::LocalVariable *CreateSyntheticVarFromEverySignature(const util::StringView &name,
                                                                   PropertySearchFlags flags) const;
    varbinder::LocalVariable *CollectSignaturesForSyntheticType(ETSFunctionType *funcType, const util::StringView &name,
                                                                PropertySearchFlags flags) const;
    bool CheckIdenticalFlags(ETSObjectFlags target) const;
    bool CheckIdenticalVariable(varbinder::Variable *otherVar) const;

    void Iterate(const PropertyTraverser &cb) const;
    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    bool SubstituteTypeArgs(TypeRelation *relation, ArenaVector<Type *> &newTypeArgs, const Substitution *substitution);
    void SetCopiedTypeProperties(TypeRelation *relation, ETSObjectType *copiedType, ArenaVector<Type *> &newTypeArgs,
                                 const Substitution *substitution);
    ETSObjectType *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    ETSObjectType *Substitute(TypeRelation *relation, const Substitution *substitution, bool cache);
    void Cast(TypeRelation *relation, Type *target) override;
    bool CastNumericObject(TypeRelation *relation, Type *target);
    bool DefaultObjectTypeChecks(const ETSChecker *etsChecker, TypeRelation *relation, Type *source);
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    Type *AsSuper(Checker *checker, varbinder::Variable *sourceVar) override;

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        ss << assemblerName_;
    }

    static void DebugInfoTypeFromName(std::stringstream &ss, util::StringView asmName);

    void ToDebugInfoType(std::stringstream &ss) const override
    {
        DebugInfoTypeFromName(ss, assemblerName_);
    }

    void ToDebugInfoSignatureType(std::stringstream &ss) const
    {
        ss << compiler::Signatures::GENERIC_BEGIN;
        ss << assemblerName_;
        ss << compiler::Signatures::GENERIC_END;
    }

    ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

    std::tuple<bool, bool> ResolveConditionExpr() const override
    {
        return {false, false};
    }

    bool IsPropertiesInstantiated() const
    {
        return propertiesInstantiated_;
    }

protected:
    virtual ETSFunctionType *CreateETSFunctionType(const util::StringView &name) const;

private:
    template <size_t... IS>
    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           ir::AstNode *declNode, ETSObjectFlags flags, TypeRelation *relation,
                           [[maybe_unused]] std::index_sequence<IS...> s)
        : Type(TypeFlag::ETS_OBJECT),
          allocator_(allocator),
          name_(name),
          assemblerName_(assemblerName),
          declNode_(declNode),
          interfaces_(allocator->Adapter()),
          flags_(flags),
          instantiationMap_(allocator->Adapter()),
          typeArguments_(allocator->Adapter()),
          relation_(relation),
          constructSignatures_(allocator->Adapter()),
          properties_ {(void(IS), PropertyMap {allocator->Adapter()})...}
    {
    }

    /* Properties and construct signatures are instantiated lazily. */
    void InstantiateProperties() const;
    void EnsurePropertiesInstantiated() const
    {
        if (!propertiesInstantiated_) {
            InstantiateProperties();
            propertiesInstantiated_ = true;
        }
    }
    ArenaMap<util::StringView, const varbinder::LocalVariable *> CollectAllProperties() const;
    bool CastWideningNarrowing(TypeRelation *relation, Type *target, TypeFlag unboxFlags, TypeFlag wideningFlags,
                               TypeFlag narrowingFlags);
    void IdenticalUptoTypeArguments(TypeRelation *relation, Type *other);
    void IsGenericSupertypeOf(TypeRelation *relation, Type *source);

    ir::TSTypeParameterDeclaration *GetTypeParams() const
    {
        if (HasObjectFlag(ETSObjectFlags::ENUM) || !HasTypeFlag(TypeFlag::GENERIC)) {
            return nullptr;
        }

        if (HasObjectFlag(ETSObjectFlags::CLASS)) {
            ASSERT(declNode_->IsClassDefinition() && declNode_->AsClassDefinition()->TypeParams());
            return declNode_->AsClassDefinition()->TypeParams();
        }

        ASSERT(declNode_->IsTSInterfaceDeclaration() && declNode_->AsTSInterfaceDeclaration()->TypeParams());
        return declNode_->AsTSInterfaceDeclaration()->TypeParams();
    }
    varbinder::LocalVariable *SearchFieldsDecls(const util::StringView &name, PropertySearchFlags flags) const;

    ArenaAllocator *allocator_;
    util::StringView name_;
    util::StringView assemblerName_;
    ir::AstNode *declNode_;
    ArenaVector<ETSObjectType *> interfaces_;
    ETSObjectFlags flags_;
    InstantiationMap instantiationMap_;
    ArenaVector<Type *> typeArguments_;
    ETSObjectType *superType_ {};
    ETSObjectType *enclosingType_ {};
    ETSObjectType *baseType_ {};

    // for lazy properties instantiation
    TypeRelation *relation_ = nullptr;
    const Substitution *substitution_ = nullptr;
    mutable bool propertiesInstantiated_ = false;
    mutable ArenaVector<Signature *> constructSignatures_;
    mutable PropertyHolder properties_;
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
