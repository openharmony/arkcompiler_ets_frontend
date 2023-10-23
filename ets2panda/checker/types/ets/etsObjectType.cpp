/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "etsObjectType.h"

#include "binder/declaration.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/types/typeFlag.h"
#include "checker/types/typeRelation.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"

namespace panda::es2panda::checker {

void ETSObjectType::Iterate(const PropertyTraverser &cb) const
{
    for (const auto *prop : GetAllProperties()) {
        cb(prop);
    }

    if (super_type_ != nullptr) {
        super_type_->Iterate(cb);
    }

    for (const auto *interface : interfaces_) {
        interface->Iterate(cb);
    }
}

binder::LocalVariable *ETSObjectType::GetProperty(const util::StringView &name, PropertySearchFlags flags) const
{
    binder::LocalVariable *res {};
    if ((flags & PropertySearchFlags::SEARCH_INSTANCE_FIELD) != 0) {
        res = GetOwnProperty<PropertyType::INSTANCE_FIELD>(name);
    }

    if (res == nullptr && ((flags & PropertySearchFlags::SEARCH_STATIC_FIELD) != 0)) {
        res = GetOwnProperty<PropertyType::STATIC_FIELD>(name);
    }

    if (res == nullptr && ((flags & PropertySearchFlags::SEARCH_INSTANCE_DECL) != 0)) {
        res = GetOwnProperty<PropertyType::INSTANCE_DECL>(name);
    }

    if (res == nullptr && ((flags & PropertySearchFlags::SEARCH_STATIC_DECL) != 0)) {
        res = GetOwnProperty<PropertyType::STATIC_DECL>(name);
    }

    if (res == nullptr && (flags & PropertySearchFlags::SEARCH_METHOD) != 0) {
        res = GetOwnProperty<PropertyType::INSTANCE_FIELD>(name);
        if (res != nullptr && res->TsType() != nullptr && res->TsType()->IsETSDynamicType()) {
            return res;
        }
        res = nullptr;
        if ((flags & PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION) != 0) {
            if ((flags & PropertySearchFlags::SEARCH_INSTANCE_METHOD) != 0) {
                res = GetOwnProperty<PropertyType::INSTANCE_METHOD>(name);
            }

            if (res == nullptr && ((flags & PropertySearchFlags::SEARCH_STATIC_METHOD) != 0)) {
                res = GetOwnProperty<PropertyType::STATIC_METHOD>(name);
            }
        } else {
            res = CreateSyntheticVarFromEverySignature(name, flags);
        }
    }

    if ((flags & (PropertySearchFlags::SEARCH_IN_INTERFACES | PropertySearchFlags::SEARCH_IN_BASE)) == 0) {
        return res;
    }

    if (res != nullptr) {
        return res;
    }

    if ((flags & PropertySearchFlags::SEARCH_IN_INTERFACES) != 0) {
        for (auto *interface : interfaces_) {
            res = interface->GetProperty(name, flags);

            if (res != nullptr) {
                return res;
            }
        }
    }

    if (super_type_ != nullptr && ((flags & PropertySearchFlags::SEARCH_IN_BASE) != 0)) {
        res = super_type_->GetProperty(name, flags);
    }

    return res;
}

binder::LocalVariable *ETSObjectType::CreateSyntheticVarFromEverySignature(const util::StringView &name,
                                                                           PropertySearchFlags flags) const
{
    binder::LocalVariable *res =
        allocator_->New<binder::LocalVariable>(binder::VariableFlags::SYNTHETIC | binder::VariableFlags::METHOD);
    ETSFunctionType *func_type = CreateETSFunctionType(name);
    func_type->AddTypeFlag(TypeFlag::SYNTHETIC);

    binder::LocalVariable *functional_interface = CollectSignaturesForSyntheticType(func_type, name, flags);

    if (functional_interface != nullptr) {
        return functional_interface;
    }

    if (func_type->CallSignatures().empty()) {
        return nullptr;
    }

    res->SetTsType(func_type);
    func_type->SetVariable(res);
    return res;
}

ETSFunctionType *ETSObjectType::CreateETSFunctionType(const util::StringView &name) const
{
    return allocator_->New<ETSFunctionType>(name, allocator_);
}

binder::LocalVariable *ETSObjectType::CollectSignaturesForSyntheticType(ETSFunctionType *func_type,
                                                                        const util::StringView &name,
                                                                        PropertySearchFlags flags) const
{
    // During function reference resolution, if the found properties type is not a function type, then it is a
    // functional interface, because no other property can be found in the methods of the class. We have to
    // return the found property, because we doesn't need to create a synthetic variable for functional
    // interfaces due to the fact, that by nature they behave as fields, and can't have overloads, and they are
    // subjected to hiding
    if ((flags & PropertySearchFlags::SEARCH_STATIC_METHOD) != 0) {
        auto *found = GetOwnProperty<PropertyType::STATIC_METHOD>(name);
        if (found != nullptr) {
            if (found->HasFlag(binder::VariableFlags::METHOD_REFERENCE)) {
                // Functional interface found
                return found;
            }

            ASSERT(found->TsType()->IsETSFunctionType());
            for (auto *it : found->TsType()->AsETSFunctionType()->CallSignatures()) {
                if (((flags & PropertySearchFlags::IGNORE_ABSTRACT) != 0) &&
                    it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
                    continue;
                }

                func_type->AddCallSignature(it);
            }
        }
    }

    if ((flags & PropertySearchFlags::SEARCH_INSTANCE_METHOD) != 0) {
        auto *found = GetOwnProperty<PropertyType::INSTANCE_METHOD>(name);
        if (found != nullptr) {
            if (found->HasFlag(binder::VariableFlags::METHOD_REFERENCE)) {
                // Functional interface found
                return found;
            }

            ASSERT(found->TsType()->IsETSFunctionType());
            for (auto *it : found->TsType()->AsETSFunctionType()->CallSignatures()) {
                if (((flags & PropertySearchFlags::IGNORE_ABSTRACT) != 0) &&
                    it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
                    continue;
                }

                func_type->AddCallSignature(it);
            }
        }
    }

    if (super_type_ != nullptr && ((flags & PropertySearchFlags::SEARCH_IN_BASE) != 0)) {
        return super_type_->CollectSignaturesForSyntheticType(func_type, name, flags);
    }

    return nullptr;
}

std::vector<binder::LocalVariable *> ETSObjectType::GetAllProperties() const
{
    std::vector<binder::LocalVariable *> all_properties;
    for (const auto &[_, prop] : InstanceFields()) {
        (void)_;
        all_properties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticFields()) {
        (void)_;
        all_properties.push_back(prop);
    }

    for (const auto &[_, prop] : InstanceMethods()) {
        (void)_;
        all_properties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticMethods()) {
        (void)_;
        all_properties.push_back(prop);
    }

    for (const auto &[_, prop] : InstanceDecls()) {
        (void)_;
        all_properties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticDecls()) {
        (void)_;
        all_properties.push_back(prop);
    }

    return all_properties;
}

std::vector<binder::LocalVariable *> ETSObjectType::Methods() const
{
    std::vector<binder::LocalVariable *> methods;
    for (const auto &[_, prop] : InstanceMethods()) {
        (void)_;
        methods.push_back(prop);
    }

    for (const auto &[_, prop] : StaticMethods()) {
        (void)_;
        methods.push_back(prop);
    }

    return methods;
}

std::vector<binder::LocalVariable *> ETSObjectType::Fields() const
{
    std::vector<binder::LocalVariable *> fields;
    for (const auto &[_, prop] : InstanceFields()) {
        (void)_;
        fields.push_back(prop);
    }

    for (const auto &[_, prop] : StaticFields()) {
        (void)_;
        fields.push_back(prop);
    }

    return fields;
}

std::vector<const binder::LocalVariable *> ETSObjectType::ForeignProperties() const
{
    std::vector<const binder::LocalVariable *> foreign_props;
    std::unordered_set<util::StringView> own_props;

    EnsurePropertiesInstantiated();
    own_props.reserve(properties_.size());

    for (const auto *prop : GetAllProperties()) {
        own_props.insert(prop->Name());
    }

    auto all_props = CollectAllProperties();
    for (const auto &[name, var] : all_props) {
        if (own_props.find(name) == own_props.end()) {
            foreign_props.push_back(var);
        }
    }

    return foreign_props;
}

std::unordered_map<util::StringView, const binder::LocalVariable *> ETSObjectType::CollectAllProperties() const
{
    std::unordered_map<util::StringView, const binder::LocalVariable *> prop_map;
    EnsurePropertiesInstantiated();
    prop_map.reserve(properties_.size());
    Iterate([&prop_map](const binder::LocalVariable *var) { prop_map.insert({var->Name(), var}); });

    return prop_map;
}

void ETSObjectType::ToString(std::stringstream &ss) const
{
    ss << name_;

    if (IsGeneric()) {
        auto const type_arguments_size = type_arguments_.size();
        ss << compiler::Signatures::GENERIC_BEGIN;
        type_arguments_[0]->ToString(ss);
        for (std::size_t i = 1U; i < type_arguments_size; ++i) {
            ss << ',';
            type_arguments_[i]->ToString(ss);
        }
        ss << compiler::Signatures::GENERIC_END;
    }

    if (IsNullableType() && this != GetConstOriginalBaseType() && !name_.Is("NullType") && !name_.Is("null") &&
        !name_.Empty()) {
        ss << "|null";
    }
}

void ETSObjectType::IdenticalUptoNullability(TypeRelation *relation, Type *other)
{
    relation->Result(false);
    if (!other->IsETSObjectType() || !CheckIdenticalFlags(other->AsETSObjectType()->ObjectFlags())) {
        return;
    }

    auto *this_base = GetOriginalBaseType();
    auto *other_base = other->AsETSObjectType()->GetOriginalBaseType();
    if (this_base->Variable() != other_base->Variable()) {
        return;
    }

    if (this_base->HasObjectFlag(ETSObjectFlags::TYPE_PARAMETER) && this_base != other_base) {
        return;
    }

    if (relation->IgnoreTypeParameters() || (this == other)) {
        relation->Result(true);
        return;
    }

    auto const other_type_arguments = other->AsETSObjectType()->TypeArguments();

    if (HasTypeFlag(TypeFlag::GENERIC) || IsNullableType()) {
        if (!HasTypeFlag(TypeFlag::GENERIC)) {
            relation->Result(true);
            return;
        }
        if (type_arguments_.empty() != other_type_arguments.empty()) {
            return;
        }
        ASSERT(type_arguments_.size() == other_type_arguments.size());
        for (size_t idx = 0; idx < type_arguments_.size(); idx++) {
            if (!(type_arguments_[idx]->IsWildcardType() || other_type_arguments[idx]->IsWildcardType())) {
                const auto get_original_base_type_or_type = [&relation](Type *const original_type) {
                    auto *const base_type = relation->GetChecker()->AsETSChecker()->GetOriginalBaseType(original_type);
                    return base_type == nullptr ? original_type : base_type;
                };

                auto *const type_arg_type = get_original_base_type_or_type(type_arguments_[idx]);
                auto *const other_type_arg_type = get_original_base_type_or_type(other_type_arguments[idx]);

                type_arg_type->Identical(relation, other_type_arg_type);

                if (!relation->IsTrue()) {
                    return;
                }
            }
        }
    } else {
        if (HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
            auto get_invoke_signature = [](const ETSObjectType *type) {
                auto const prop_invoke =
                    type->GetProperty(util::StringView("invoke"), PropertySearchFlags::SEARCH_INSTANCE_METHOD);
                ASSERT(prop_invoke != nullptr);
                return prop_invoke->TsType()->AsETSFunctionType()->CallSignatures()[0];
            };

            auto *const this_invoke_signature = get_invoke_signature(this);
            auto *const other_invoke_signature = get_invoke_signature(other->AsETSObjectType());

            relation->IsIdenticalTo(this_invoke_signature, other_invoke_signature);
            return;
        }
    }

    relation->Result(true);
}

void ETSObjectType::Identical(TypeRelation *relation, Type *other)
{
    if (IsNullableType() != other->IsNullableType()) {
        return;
    }
    IdenticalUptoNullability(relation, other);
}

bool ETSObjectType::CheckIdenticalFlags(ETSObjectFlags target) const
{
    auto cleaned_target_flags = static_cast<ETSObjectFlags>(target & (~ETSObjectFlags::COMPLETELY_RESOLVED));
    cleaned_target_flags &= ~ETSObjectFlags::INCOMPLETE_INSTANTIATION;
    cleaned_target_flags &= ~ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS;
    cleaned_target_flags &= ~ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY;
    auto cleaned_self_flags = static_cast<ETSObjectFlags>(ObjectFlags() & (~ETSObjectFlags::COMPLETELY_RESOLVED));
    cleaned_self_flags &= ~ETSObjectFlags::INCOMPLETE_INSTANTIATION;
    cleaned_self_flags &= ~ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS;
    cleaned_self_flags &= ~ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY;
    return cleaned_self_flags == cleaned_target_flags;
}

bool ETSObjectType::AssignmentSource(TypeRelation *const relation, Type *const target)
{
    relation->Result(IsETSNullType() && target->IsNullableType());

    return relation->IsTrue();
}

void ETSObjectType::AssignmentTarget(TypeRelation *const relation, Type *source)
{
    if (source->IsETSNullType()) {
        relation->Result(IsNullableType());
        return;
    }

    if (source->IsNullableType() && !IsNullableType()) {
        return;
    }

    if (HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        EnsurePropertiesInstantiated();
        auto found = properties_[static_cast<size_t>(PropertyType::INSTANCE_METHOD)].find("invoke");
        ASSERT(found != properties_[static_cast<size_t>(PropertyType::INSTANCE_METHOD)].end());
        relation->IsAssignableTo(source, found->second->TsType());
        return;
    }

    IsSupertypeOf(relation, source);
}

void ETSObjectType::Cast(TypeRelation *const relation, Type *const target)
{
    conversion::Identity(relation, this, target);
    if (relation->IsTrue()) {
        return;
    }

    if (this->HasObjectFlag(ETSObjectFlags::NULL_TYPE)) {
        if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
            relation->GetNode()->SetTsType(target);
            relation->Result(true);
            return;
        }

        conversion::Forbidden(relation);
        return;
    }

    if (!this->IsNullableType()) {
        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_BYTE)) {
            if (target->HasTypeFlag(TypeFlag::BYTE)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::SHORT | TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT |
                                    TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_SHORT)) {
            if (target->HasTypeFlag(TypeFlag::SHORT)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
            if (target->HasTypeFlag(TypeFlag::CHAR)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_INT)) {
            if (target->HasTypeFlag(TypeFlag::INT)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_LONG)) {
            if (target->HasTypeFlag(TypeFlag::LONG)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_FLOAT)) {
            if (target->HasTypeFlag(TypeFlag::FLOAT)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::DOUBLE)) {
                conversion::UnboxingWideningPrimitive(relation, this, target);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_DOUBLE)) {
            if (target->HasTypeFlag(TypeFlag::DOUBLE)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN)) {
            if (target->HasTypeFlag(TypeFlag::ETS_BOOLEAN)) {
                conversion::Unboxing(relation, this);
                return;
            }

            if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
                conversion::WideningReference(relation, this, target->AsETSObjectType());
                return;
            }

            conversion::Forbidden(relation);
            return;
        }

        if (target->HasTypeFlag(TypeFlag::BYTE | TypeFlag::SHORT | TypeFlag::CHAR | TypeFlag::INT | TypeFlag::LONG |
                                TypeFlag::FLOAT | TypeFlag::DOUBLE | TypeFlag::ETS_BOOLEAN)) {
            conversion::NarrowingReferenceUnboxing(relation, this, target);
            return;
        }
    }

    if (target->HasTypeFlag(TypeFlag::ETS_ARRAY)) {
        conversion::NarrowingReference(relation, this, target->AsETSArrayType());
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        conversion::WideningReference(relation, this, target->AsETSObjectType());
        if (relation->IsTrue()) {
            return;
        }

        conversion::NarrowingReference(relation, this, target->AsETSObjectType());
        if (relation->IsTrue()) {
            return;
        }
    }

    conversion::Forbidden(relation);
}

void ETSObjectType::IsSupertypeOf(TypeRelation *relation, Type *source)
{
    relation->Result(false);
    auto *const ets_checker = relation->GetChecker()->AsETSChecker();

    // 3.8.3 Subtyping among Array Types
    auto const *const base = GetConstOriginalBaseType();
    if (base == ets_checker->GlobalETSObjectType() && source->IsETSArrayType()) {
        relation->Result(true);
        return;
    }

    if (!source->IsETSObjectType() ||
        !source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::CLASS | ETSObjectFlags::INTERFACE)) {
        return;
    }

    if (!IsNullableType() && source->IsNullableType()) {
        return;
    }

    // All classes and interfaces are subtypes of Object
    if (base == ets_checker->GlobalETSObjectType()) {
        relation->Result(true);
        return;
    }

    IdenticalUptoNullability(relation, source);
    if (relation->IsTrue()) {
        return;
    }

    ETSObjectType *source_obj = source->AsETSObjectType();
    if (auto *source_super = source_obj->SuperType(); source_super != nullptr) {
        IsSupertypeOf(relation, source_super);
        if (relation->IsTrue()) {
            return;
        }
    }

    if (HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        for (auto *itf : source_obj->Interfaces()) {
            IsSupertypeOf(relation, itf);
            if (relation->IsTrue()) {
                return;
            }
        }
    }
}

Type *ETSObjectType::AsSuper(Checker *checker, binder::Variable *source_var)
{
    if (source_var == nullptr) {
        return nullptr;
    }

    if (variable_ == source_var) {
        return this;
    }

    if (HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        Type *res = nullptr;
        for (auto *const it : checker->AsETSChecker()->GetInterfaces(this)) {
            res = it->AsSuper(checker, source_var);
            if (res != nullptr) {
                return res;
            }
        }
        return checker->GetGlobalTypesHolder()->GlobalETSObjectType()->AsSuper(checker, source_var);
    }

    Type *const super_type = checker->AsETSChecker()->GetSuperType(this);

    if (super_type == nullptr) {
        return nullptr;
    }

    if (!super_type->IsETSObjectType()) {
        return nullptr;
    }

    if (ETSObjectType *const super_obj = super_type->AsETSObjectType();
        super_obj->HasObjectFlag(ETSObjectFlags::CLASS)) {
        Type *const res = super_obj->AsSuper(checker, source_var);
        if (res != nullptr) {
            return res;
        }
    }

    if (source_var->TsType()->IsETSObjectType() &&
        source_var->TsType()->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        for (auto *const it : checker->AsETSChecker()->GetInterfaces(this)) {
            Type *const res = it->AsSuper(checker, source_var);
            if (res != nullptr) {
                return res;
            }
        }
    }

    return nullptr;
}

binder::LocalVariable *ETSObjectType::CopyProperty(binder::LocalVariable *prop, ArenaAllocator *allocator,
                                                   TypeRelation *relation, GlobalTypesHolder *global_types)
{
    auto *const copied_prop = prop->Copy(allocator, prop->Declaration());
    auto *const copied_prop_type = ETSChecker::TryToInstantiate(
        relation->GetChecker()->AsETSChecker()->GetTypeOfVariable(prop), allocator, relation, global_types);
    // NOTE: don't change type variable if it differs from copying one!
    if (copied_prop_type->Variable() == prop) {
        copied_prop_type->SetVariable(copied_prop);
    }
    copied_prop->SetTsType(copied_prop_type);
    return copied_prop;
}

Type *ETSObjectType::Instantiate(ArenaAllocator *const allocator, TypeRelation *const relation,
                                 GlobalTypesHolder *const global_types)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    std::lock_guard guard {*checker->Mutex()};
    auto *const base = GetOriginalBaseType();

    if (!relation->TypeInstantiationPossible(base) || IsETSNullType()) {
        return this;
    }
    relation->IncreaseTypeRecursionCount(base);

    auto *const copied_type = checker->CreateNewETSObjectType(name_, decl_node_, flags_);
    copied_type->type_flags_ = type_flags_;
    copied_type->RemoveObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS |
                                  ETSObjectFlags::INCOMPLETE_INSTANTIATION | ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
    copied_type->SetAssemblerName(assembler_name_);
    copied_type->SetVariable(variable_);
    copied_type->SetSuperType(super_type_);

    for (auto *const it : interfaces_) {
        copied_type->AddInterface(it);
    }

    for (auto *const type_argument : TypeArguments()) {
        copied_type->TypeArguments().emplace_back(type_argument->Instantiate(allocator, relation, global_types));
    }

    copied_type->SetBaseType(this);
    copied_type->properties_instantiated_ = false;
    copied_type->relation_ = relation;
    copied_type->substitution_ = nullptr;

    relation->DecreaseTypeRecursionCount(base);

    return copied_type;
}

static binder::LocalVariable *CopyPropertyWithTypeArguments(binder::LocalVariable *prop, TypeRelation *relation,
                                                            const Substitution *substitution)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const copied_prop_type = checker->GetTypeOfVariable(prop)->Substitute(relation, substitution);
    auto *const copied_prop = prop->Copy(checker->Allocator(), prop->Declaration());
    copied_prop_type->SetVariable(copied_prop);
    copied_prop->SetTsType(copied_prop_type);
    return copied_prop;
}

ETSObjectType const *ETSObjectType::GetConstOriginalBaseType() const noexcept
{
    if (auto *base_iter = GetBaseType(); base_iter != nullptr) {
        auto *base_iter_next = base_iter->GetBaseType();
        while (base_iter_next != nullptr && base_iter_next != base_iter) {
            base_iter = base_iter_next;
            base_iter_next = base_iter->GetBaseType();
        }
        return base_iter;
    }
    return this;
}

Type *ETSObjectType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *base = GetOriginalBaseType();
    if (auto repl = substitution->find(base); repl != substitution->end()) {
        auto *repl_type = repl->second;

        /* Any other flags we need to copy? */

        /* The check this != base is a kludge to distinguish bare type parameter T
           with a nullable constraint (like the default Object|null) from explicitly nullable
           T|null
        */
        if (IsNullableType() && this != base && !repl_type->IsNullableType()) {
            // this type is explicitly marked as nullable
            ASSERT(repl_type->IsETSObjectType() || repl_type->IsETSArrayType() || repl_type->IsETSFunctionType());
            auto *new_repl_type =
                repl_type->Instantiate(checker->Allocator(), relation, checker->GetGlobalTypesHolder());
            new_repl_type->AddTypeFlag(TypeFlag::NULLABLE);
            repl_type = new_repl_type;
        }
        return repl_type;
    }

    ArenaVector<Type *> new_type_args {checker->Allocator()->Adapter()};
    new_type_args.reserve(type_arguments_.size());
    bool any_change = false;
    for (auto *arg : type_arguments_) {
        auto *new_arg = arg->Substitute(relation, substitution);
        new_type_args.push_back(new_arg);
        any_change |= (new_arg != arg);
    }

    // Lambda types can capture type params in their bodies, normal classes cannot.
    // TODO(gogabr): determine precise conditions where we do not need to copy.
    // Perhaps keep track of captured type parameters for each type.
    if (!any_change && !HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        return this;
    }

    const util::StringView hash = checker->GetHashFromSubstitution(substitution);
    if (auto *inst = GetInstantiatedType(hash); inst != nullptr) {
        return inst;
    }

    if ((!relation->TypeInstantiationPossible(base)) || IsETSNullType()) {
        return this;
    }
    relation->IncreaseTypeRecursionCount(base);

    auto *const copied_type = checker->CreateNewETSObjectType(name_, decl_node_, flags_);
    copied_type->type_flags_ = type_flags_;
    copied_type->RemoveObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS |
                                  ETSObjectFlags::INCOMPLETE_INSTANTIATION | ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
    copied_type->SetVariable(variable_);
    copied_type->SetBaseType(this);

    copied_type->SetTypeArguments(std::move(new_type_args));
    copied_type->relation_ = relation;
    copied_type->substitution_ = substitution;

    GetInstantiationMap().try_emplace(hash, copied_type);

    if (super_type_ != nullptr) {
        copied_type->SetSuperType(super_type_->Substitute(relation, substitution)->AsETSObjectType());
    }
    for (auto *itf : interfaces_) {
        auto *new_itf = itf->Substitute(relation, substitution)->AsETSObjectType();
        copied_type->AddInterface(new_itf);
    }

    relation->DecreaseTypeRecursionCount(base);

    return copied_type;
}

void ETSObjectType::InstantiateProperties() const
{
    if (base_type_ == nullptr || base_type_ == this) {
        return;
    }
    ASSERT(!properties_instantiated_);
    ASSERT(relation_ != nullptr);

    for (auto *const it : base_type_->ConstructSignatures()) {
        auto *new_sig = it->Substitute(relation_, substitution_);
        construct_signatures_.push_back(new_sig);
    }

    for (auto const &[_, prop] : base_type_->InstanceFields()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_FIELD)].emplace(prop->Name(), copied_prop);
    }

    for (auto const &[_, prop] : base_type_->StaticFields()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_FIELD)].emplace(prop->Name(), copied_prop);
    }

    for (auto const &[_, prop] : base_type_->InstanceMethods()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_METHOD)].emplace(prop->Name(), copied_prop);
    }

    for (auto const &[_, prop] : base_type_->StaticMethods()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_METHOD)].emplace(prop->Name(), copied_prop);
    }

    for (auto const &[_, prop] : base_type_->InstanceDecls()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_DECL)].emplace(prop->Name(), copied_prop);
    }

    for (auto const &[_, prop] : base_type_->StaticDecls()) {
        (void)_;
        auto *copied_prop = CopyPropertyWithTypeArguments(prop, relation_, substitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_DECL)].emplace(prop->Name(), copied_prop);
    }
}

}  // namespace panda::es2panda::checker
