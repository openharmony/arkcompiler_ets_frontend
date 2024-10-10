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
#include "checker/types/ets/etsObjectTypeConstants.h"
#include "checker/types/signature.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "varbinder/scope.h"
#include "ir/base/classDefinition.h"

namespace ark::es2panda::checker {
using PropertyProcesser = std::function<varbinder::LocalVariable *(varbinder::LocalVariable *, Type *)>;
class ETSObjectType : public Type {
public:
    using PropertyMap = ArenaUnorderedMap<util::StringView, varbinder::LocalVariable *>;
    using InstantiationMap = ArenaUnorderedMap<util::StringView, ETSObjectType *>;
    using PropertyTraverser = std::function<void(const varbinder::LocalVariable *)>;
    using PropertyHolder = std::array<PropertyMap, static_cast<size_t>(PropertyType::COUNT)>;

    explicit ETSObjectType(ArenaAllocator *allocator) : ETSObjectType(allocator, ETSObjectFlags::NO_OPTS) {}

    explicit ETSObjectType(ArenaAllocator *allocator, ETSObjectFlags flags)
        : ETSObjectType(allocator, "", "", std::make_tuple(nullptr, flags, nullptr))
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, ETSObjectFlags flags, TypeRelation *relation)
        : ETSObjectType(allocator, "", "", std::make_tuple(nullptr, flags, relation))
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           ir::AstNode *declNode, ETSObjectFlags flags)
        : ETSObjectType(allocator, name, assemblerName, std::make_tuple(declNode, flags, nullptr),
                        std::make_index_sequence<static_cast<size_t>(PropertyType::COUNT)> {})
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           std::tuple<ir::AstNode *, ETSObjectFlags, TypeRelation *> info)
        : ETSObjectType(allocator, name, assemblerName, info,
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

    bool IsPropertyInherited(const varbinder::Variable *var);

    bool IsPropertyOfAscendant(const varbinder::Variable *var) const;

    bool IsSignatureInherited(Signature *signature);

    bool IsDescendantOf(const ETSObjectType *ascendant) const;

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

    template <PropertyType TYPE>
    void AddProperty(varbinder::LocalVariable *prop, util::StringView localName) const
    {
        util::StringView nameToAccess = prop->Name();

        if (!localName.Empty()) {
            nameToAccess = localName;
        }

        properties_[static_cast<size_t>(TYPE)].emplace(nameToAccess, prop);
        propertiesInstantiated_ = true;
    }

    template <PropertyType TYPE>
    void RemoveProperty(varbinder::LocalVariable *prop)
    {
        properties_[static_cast<size_t>(TYPE)].erase(prop->Name());
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
    bool CheckIdenticalFlags(ETSObjectType *other) const;
    bool CheckIdenticalVariable(varbinder::Variable *otherVar) const;

    void Iterate(const PropertyTraverser &cb) const;
    void ToString(std::stringstream &ss, bool precise) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *globalTypes) override;
    void UpdateTypeProperties(checker::ETSChecker *checker, PropertyProcesser const &func);
    ETSObjectType *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    ETSObjectType *Substitute(TypeRelation *relation, const Substitution *substitution, bool cache);
    ETSObjectType *SubstituteArguments(TypeRelation *relation, ArenaVector<Type *> const &arguments);
    void Cast(TypeRelation *relation, Type *target) override;
    bool CastNumericObject(TypeRelation *relation, Type *target);
    bool DefaultObjectTypeChecks(const ETSChecker *etsChecker, TypeRelation *relation, Type *source);
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    Type *AsSuper(Checker *checker, varbinder::Variable *sourceVar) override;
    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override;
    static void DebugInfoTypeFromName(std::stringstream &ss, util::StringView asmName);
    void ToDebugInfoType(std::stringstream &ss) const override;
    void ToDebugInfoSignatureType(std::stringstream &ss) const;

    void AddReExports(ETSObjectType *reExport);
    void AddReExportAlias(util::StringView const &value, util::StringView const &key);
    util::StringView GetReExportAliasValue(util::StringView const &key) const;
    bool IsReExportHaveAliasValue(util::StringView const &key) const;
    const ArenaVector<ETSObjectType *> &ReExports() const;

    ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

    std::tuple<bool, bool> ResolveConditionExpr() const override
    {
        return {false, false};
    }

    [[nodiscard]] static std::uint32_t GetPrecedence(checker::ETSChecker *checker, ETSObjectType const *type) noexcept;

    bool IsPropertiesInstantiated() const
    {
        return propertiesInstantiated_;
    }

protected:
    virtual ETSFunctionType *CreateETSFunctionType(const util::StringView &name) const;

private:
    template <size_t... IS>
    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assemblerName,
                           std::tuple<ir::AstNode *, ETSObjectFlags, TypeRelation *> info,
                           [[maybe_unused]] std::index_sequence<IS...> s)
        : Type(TypeFlag::ETS_OBJECT),
          allocator_(allocator),
          name_(name),
          assemblerName_(assemblerName),
          declNode_(std::get<ir::AstNode *>(info)),
          interfaces_(allocator->Adapter()),
          reExports_(allocator->Adapter()),
          reExportAlias_(allocator->Adapter()),
          flags_(std::get<ETSObjectFlags>(info)),
          instantiationMap_(allocator->Adapter()),
          typeArguments_(allocator->Adapter()),
          relation_(std::get<TypeRelation *>(info)),
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
    void UpdateTypeProperty(checker::ETSChecker *checker, varbinder::LocalVariable *const prop, PropertyType fieldType,
                            PropertyProcesser const &func);

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

    void SetCopiedTypeProperties(TypeRelation *relation, ETSObjectType *copiedType, ArenaVector<Type *> &&newTypeArgs,
                                 ETSObjectType *base);
    bool SubstituteTypeArgs(TypeRelation *relation, ArenaVector<Type *> &newTypeArgs, const Substitution *substitution);

    bool TryCastByte(TypeRelation *const relation, Type *const target);
    bool TryCastIntegral(TypeRelation *const relation, Type *const target);
    bool TryCastFloating(TypeRelation *const relation, Type *const target);
    bool TryCastUnboxable(TypeRelation *const relation, Type *const target);

    ArenaAllocator *allocator_;
    util::StringView name_;
    util::StringView assemblerName_;
    ir::AstNode *declNode_;
    ArenaVector<ETSObjectType *> interfaces_;
    ArenaVector<ETSObjectType *> reExports_;
    ArenaMap<util::StringView, util::StringView> reExportAlias_;
    ETSObjectFlags flags_;
    InstantiationMap instantiationMap_;
    ArenaVector<Type *> typeArguments_;
    ETSObjectType *superType_ {};
    ETSObjectType *enclosingType_ {};
    ETSObjectType *baseType_ {};

    // for lazy properties instantiation
    TypeRelation *relation_ = nullptr;
    const Substitution *effectiveSubstitution_ = nullptr;
    mutable bool propertiesInstantiated_ = false;
    mutable ArenaVector<Signature *> constructSignatures_;
    mutable PropertyHolder properties_;
};
}  // namespace ark::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
