/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "plugins/ecmascript/es2panda/checker/types/type.h"
#include "plugins/ecmascript/es2panda/checker/types/signature.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsInterfaceDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameterDeclaration.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"

namespace panda::es2panda::checker {

enum class ETSObjectFlags : uint32_t {
    NO_OPTS = 0U,
    CLASS = 1U << 0U,
    INTERFACE = 1U << 1U,
    INSTANCE = 1U << 2U,
    ABSTRACT = 1U << 3U,
    GLOBAL = 1U << 4U,
    ENUM = 1U << 5U,
    FUNCTIONAL = 1U << 6U,
    RESOLVED_MEMBERS = 1U << 7U,
    RESOLVED_INTERFACES = 1U << 8U,
    RESOLVED_SUPER = 1U << 9U,
    RESOLVED_TYPE_PARAMS = 1U << 10U,
    CHECKED_COMPATIBLE_ABSTRACTS = 1U << 11U,
    NULL_TYPE = 1U << 12U,
    STRING = 1U << 13U,
    INCOMPLETE_INSTANTIATION = 1U << 14U,
    INNER = 1U << 15U,
    DYNAMIC = 1U << 16U,
    ASYNC_FUNC_RETURN_TYPE = 1U << 17U,
    TYPE_PARAMETER = 1U << 18U,

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
    BUILTIN_TYPE = BUILTIN_STRING | UNBOXABLE_TYPE,
    VALID_SWITCH_TYPE =
        BUILTIN_BYTE | BUILTIN_CHAR | BUILTIN_SHORT | BUILTIN_INT | BUILTIN_LONG | BUILTIN_STRING | ENUM,
    GLOBAL_CLASS = CLASS | GLOBAL,
    FUNCTIONAL_INTERFACE = INTERFACE | ABSTRACT | FUNCTIONAL,
    COMPLETELY_RESOLVED = RESOLVED_MEMBERS | RESOLVED_INTERFACES | RESOLVED_SUPER | RESOLVED_TYPE_PARAMS,
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
    IS_SETTER = 1U << 11U,
    IS_GETTER = 1U << 12U,

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

class ETSObjectType : public Type {
public:
    using PropertyMap = ArenaUnorderedMap<util::StringView, binder::LocalVariable *>;
    using InstantiationMap = ArenaUnorderedMap<util::StringView, ETSObjectType *>;
    using PropertyTraverser = std::function<void(const binder::LocalVariable *)>;
    using PropertyHolder = std::array<PropertyMap, static_cast<size_t>(PropertyType::COUNT)>;

    explicit ETSObjectType(ArenaAllocator *allocator) : ETSObjectType(allocator, ETSObjectFlags::NO_OPTS) {}

    explicit ETSObjectType(ArenaAllocator *allocator, ETSObjectFlags flags)
        : ETSObjectType(allocator, "", "", nullptr, flags)
    {
    }

    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assembler_name,
                           ir::AstNode *decl_node, ETSObjectFlags flags)
        : ETSObjectType(allocator, name, assembler_name, decl_node, flags,
                        std::make_index_sequence<static_cast<size_t>(PropertyType::COUNT)> {})
    {
    }

    void AddConstructSignature(Signature *signature)
    {
        construct_signatures_.push_back(signature);
        properties_instantiated_ = true;
    }

    void AddConstructSignature(const ArenaVector<Signature *> &signatures)
    {
        construct_signatures_.insert(construct_signatures_.end(), signatures.begin(), signatures.end());
        properties_instantiated_ = true;
    }

    void AddInterface(ETSObjectType *interface)
    {
        if (std::find(interfaces_.begin(), interfaces_.end(), interface) == interfaces_.end()) {
            interfaces_.push_back(interface);
        }
    }

    void SetSuperType(ETSObjectType *super)
    {
        super_type_ = super;
    }

    void SetTypeArguments(ArenaVector<Type *> &&type_args)
    {
        type_arguments_ = std::move(type_args);
    }

    void SetEnclosingType(ETSObjectType *enclosing_type)
    {
        enclosing_type_ = enclosing_type;
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
        return type_arguments_;
    }

    ArenaVector<Type *> &TypeArguments()
    {
        return type_arguments_;
    }

    const ArenaVector<Signature *> &ConstructSignatures() const
    {
        EnsurePropertiesInstantiated();
        return construct_signatures_;
    }

    ArenaVector<Signature *> &ConstructSignatures()
    {
        EnsurePropertiesInstantiated();
        return construct_signatures_;
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
        return decl_node_;
    }

    const ETSObjectType *SuperType() const
    {
        return super_type_;
    }

    ETSObjectType *SuperType()
    {
        return super_type_;
    }

    const ETSObjectType *EnclosingType() const
    {
        return enclosing_type_;
    }

    ETSObjectType *EnclosingType()
    {
        return enclosing_type_;
    }

    ETSObjectType *OutermostClass()
    {
        auto *iter = enclosing_type_;

        while (iter != nullptr && iter->EnclosingType() != nullptr) {
            iter = iter->EnclosingType();
        }

        return iter;
    }

    void SetBaseType(ETSObjectType *base_type)
    {
        base_type_ = base_type;
    }

    ETSObjectType *GetBaseType()
    {
        return base_type_;
    }

    const ETSObjectType *GetBaseType() const
    {
        return base_type_;
    }

    bool IsPropertyInherited(const binder::Variable *var)
    {
        if (var->HasFlag(binder::VariableFlags::PRIVATE)) {
            return GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) ==
                   var;
        }

        if (var->HasFlag(binder::VariableFlags::PROTECTED)) {
            return (GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) ==
                    var) ||
                   this->IsPropertyOfAscendant(var);
        }

        return true;
    }

    bool IsPropertyOfAscendant(const binder::Variable *var)
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

    bool IsDescendantOf(const ETSObjectType *ascendant)
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
        return assembler_name_;
    }

    void SetName(const util::StringView &new_name)
    {
        name_ = new_name;
    }

    void SetAssemblerName(const util::StringView &new_name)
    {
        assembler_name_ = new_name;
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

    ETSFunctionType *GetFunctionalInterfaceInvokeType()
    {
        ASSERT(HasObjectFlag(ETSObjectFlags::FUNCTIONAL));
        auto *invoke = GetOwnProperty<PropertyType::INSTANCE_METHOD>("invoke");
        ASSERT(invoke && invoke->TsType() && invoke->TsType()->IsETSFunctionType());
        return invoke->TsType()->AsETSFunctionType();
    }

    ETSObjectFlags BuiltInKind()
    {
        return static_cast<checker::ETSObjectFlags>(flags_ & ETSObjectFlags::BUILTIN_TYPE);
    }

    ETSObjectType *GetInstantiatedType(util::StringView hash)
    {
        auto found = instantiation_map_.find(hash);

        if (found != instantiation_map_.end()) {
            return found->second;
        }

        return nullptr;
    }

    binder::Scope *GetTypeArgumentScope() const
    {
        if (HasObjectFlag(ETSObjectFlags::ENUM) || !HasTypeFlag(TypeFlag::GENERIC)) {
            return nullptr;
        }

        if (HasObjectFlag(ETSObjectFlags::CLASS)) {
            ASSERT(decl_node_->IsClassDefinition() && decl_node_->AsClassDefinition()->TypeParams());
            return decl_node_->AsClassDefinition()->TypeParams()->Scope();
        }

        ASSERT(decl_node_->IsTSInterfaceDeclaration() && decl_node_->AsTSInterfaceDeclaration()->TypeParams());
        return decl_node_->AsTSInterfaceDeclaration()->TypeParams()->Scope();
    }

    InstantiationMap &GetInstantiationMap()
    {
        return instantiation_map_;
    }

    template <PropertyType TYPE>
    binder::LocalVariable *GetOwnProperty(const util::StringView &name) const
    {
        EnsurePropertiesInstantiated();
        auto found = properties_[static_cast<size_t>(TYPE)].find(name);
        if (found != properties_[static_cast<size_t>(TYPE)].end()) {
            return found->second;
        }
        return nullptr;
    }

    template <PropertyType TYPE>
    void AddProperty(binder::LocalVariable *prop)
    {
        properties_[static_cast<size_t>(TYPE)].emplace(prop->Name(), prop);
        properties_instantiated_ = true;
    }

    std::vector<const binder::LocalVariable *> ForeignProperties() const;
    binder::LocalVariable *GetProperty(const util::StringView &name, PropertySearchFlags flags) const;
    std::vector<binder::LocalVariable *> GetAllProperties() const;
    void CreatePropertyMap(ArenaAllocator *allocator);
    binder::LocalVariable *CopyProperty(binder::LocalVariable *prop, ArenaAllocator *allocator, TypeRelation *relation,
                                        GlobalTypesHolder *global_types);
    std::vector<binder::LocalVariable *> Methods() const;
    std::vector<binder::LocalVariable *> Fields() const;
    binder::LocalVariable *CreateSyntheticVarFromEverySignature(const util::StringView &name,
                                                                PropertySearchFlags flags) const;
    binder::LocalVariable *CollectSignaturesForSyntheticType(ETSFunctionType *func_type, const util::StringView &name,
                                                             PropertySearchFlags flags) const;
    bool CheckIdenticalFlags(ETSObjectFlags target) const;
    bool CheckIdenticalVariable(binder::Variable *other_var) const;

    void Iterate(const PropertyTraverser &cb) const;
    void ToString(std::stringstream &ss) const override;
    void Identical(TypeRelation *relation, Type *other) override;
    bool AssignmentSource(TypeRelation *relation, Type *target) override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;
    Type *Instantiate(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types) override;
    Type *Substitute(TypeRelation *relation, const Substitution *substitution) override;
    void Cast(TypeRelation *relation, Type *target) override;
    void IsSupertypeOf(TypeRelation *relation, Type *source) override;
    Type *AsSuper(Checker *checker, binder::Variable *source_var) override;

    void ToAssemblerType([[maybe_unused]] std::stringstream &ss) const override
    {
        ss << assembler_name_;
    }

    void ToDebugInfoType(std::stringstream &ss) const override
    {
        ss << compiler::Signatures::CLASS_REF_BEGIN;
        auto name = assembler_name_.Mutf8();
        std::replace(name.begin(), name.end(), *compiler::Signatures::METHOD_SEPARATOR.begin(),
                     *compiler::Signatures::NAMESPACE_SEPARATOR.begin());
        ss << name;
        ss << compiler::Signatures::MANGLE_SEPARATOR;
    }

    void ToDebugInfoSignatureType(std::stringstream &ss) const
    {
        ss << compiler::Signatures::GENERIC_BEGIN;
        ss << assembler_name_;
        ss << compiler::Signatures::GENERIC_END;
    }

    ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

private:
    template <size_t... IS>
    explicit ETSObjectType(ArenaAllocator *allocator, util::StringView name, util::StringView assembler_name,
                           ir::AstNode *decl_node, ETSObjectFlags flags, [[maybe_unused]] std::index_sequence<IS...> s)
        : Type(TypeFlag::ETS_OBJECT),
          allocator_(allocator),
          name_(name),
          assembler_name_(assembler_name),
          decl_node_(decl_node),
          interfaces_(allocator->Adapter()),
          flags_(flags),
          instantiation_map_(allocator->Adapter()),
          type_arguments_(allocator->Adapter()),
          construct_signatures_(allocator->Adapter()),
          properties_ {(void(IS), PropertyMap {allocator->Adapter()})...}
    {
    }

    /* Properties and construct signatures are instantiated lazily. */
    void InstantiateProperties() const;
    void EnsurePropertiesInstantiated() const
    {
        if (!properties_instantiated_) {
            InstantiateProperties();
            properties_instantiated_ = true;
        }
    }
    std::unordered_map<util::StringView, const binder::LocalVariable *> CollectAllProperties() const;
    void IdenticalUptoNullability(TypeRelation *relation, Type *other);

    ArenaAllocator *allocator_;
    util::StringView name_;
    util::StringView assembler_name_;
    ir::AstNode *decl_node_;
    ArenaVector<ETSObjectType *> interfaces_;
    ETSObjectFlags flags_;
    InstantiationMap instantiation_map_;
    ArenaVector<Type *> type_arguments_;
    ETSObjectType *super_type_ {};
    ETSObjectType *enclosing_type_ {};
    ETSObjectType *base_type_ {};

    // for lazy properties instantiation
    TypeRelation *relation_ = nullptr;
    const Substitution *substitution_ = nullptr;
    mutable bool properties_instantiated_ = false;
    mutable ArenaVector<Signature *> construct_signatures_;
    mutable PropertyHolder properties_;
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_FUNCTION_TYPE_H */
