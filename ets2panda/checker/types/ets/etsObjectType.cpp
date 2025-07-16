/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/types/globalTypesHolder.h"

namespace ark::es2panda::checker {

void ETSObjectType::Iterate(const PropertyTraverser &cb) const
{
    for (const auto *prop : GetAllProperties()) {
        cb(prop);
    }

    if (superType_ != nullptr) {
        superType_->Iterate(cb);
    }

    for (const auto *interface : interfaces_) {
        interface->Iterate(cb);
    }
}

varbinder::LocalVariable *ETSObjectType::SearchFieldsDecls(const util::StringView &name,
                                                           PropertySearchFlags flags) const
{
    varbinder::LocalVariable *res {};
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
    return res;
}

varbinder::LocalVariable *ETSObjectType::GetProperty(const util::StringView &name, PropertySearchFlags flags) const
{
    varbinder::LocalVariable *res = SearchFieldsDecls(name, flags);
    if (res == nullptr && (flags & PropertySearchFlags::SEARCH_METHOD) != 0) {
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

    if (res == nullptr && (flags & PropertySearchFlags::SEARCH_IN_INTERFACES) != 0) {
        for (auto *interface : interfaces_) {
            res = interface->GetProperty(name, flags);
            if (res != nullptr) {
                return res;
            }
        }
    }

    if (res == nullptr && superType_ != nullptr && ((flags & PropertySearchFlags::SEARCH_IN_BASE) != 0)) {
        res = superType_->GetProperty(name, flags);
    }

    return res;
}

bool ETSObjectType::IsPropertyInherited(const varbinder::Variable *var)
{
    if (var->HasFlag(varbinder::VariableFlags::PRIVATE)) {
        return GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) == var;
    }

    if (var->HasFlag(varbinder::VariableFlags::PROTECTED)) {
        return (GetProperty(var->Name(), PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) ==
                var) ||
               this->IsPropertyOfAscendant(var);
    }

    return true;
}

bool ETSObjectType::IsPropertyOfAscendant(const varbinder::Variable *var) const
{
    if (this->SuperType() == nullptr) {
        return false;
    }

    if (this->SuperType()->GetProperty(var->Name(),
                                       PropertySearchFlags::SEARCH_FIELD | PropertySearchFlags::SEARCH_DECL) == var) {
        return true;
    }

    return this->SuperType()->IsPropertyOfAscendant(var);
}

bool ETSObjectType::IsSignatureInherited(Signature *signature)
{
    if (signature->HasSignatureFlag(SignatureFlags::PRIVATE)) {
        return signature->Owner() == this;
    }

    if (signature->HasSignatureFlag(SignatureFlags::PROTECTED)) {
        return signature->Owner() == this || this->IsDescendantOf(signature->Owner());
    }

    return true;
}

bool ETSObjectType::IsDescendantOf(const ETSObjectType *ascendant) const
{
    if (this->SuperType() == nullptr) {
        return false;
    }

    if (this->SuperType() == ascendant) {
        return true;
    }

    return this->SuperType()->IsDescendantOf(ascendant);
}

static bool HasAccessor(const PropertySearchFlags &flags, const ETSFunctionType *funcType)
{
    if ((flags & (PropertySearchFlags::IS_GETTER | PropertySearchFlags::IS_SETTER)) != 0) {
        return true;
    }
    return funcType->HasTypeFlag(TypeFlag::GETTER) || funcType->HasTypeFlag(TypeFlag::SETTER);
}

static void UpdateDeclarationForGetterSetter(varbinder::LocalVariable *res, const ETSFunctionType *funcType,
                                             const PropertySearchFlags &flags)
{
    if (!HasAccessor(flags, funcType) || res->Declaration() != nullptr) {
        return;
    }
    auto var = funcType->CallSignatures().front()->OwnerVar();
    auto decl = var->Declaration();
    if (decl == nullptr || decl->Node() == nullptr) {
        return;
    }
    res->Reset(decl, var->Flags());
}

varbinder::LocalVariable *ETSObjectType::CreateSyntheticVarFromEverySignature(const util::StringView &name,
                                                                              PropertySearchFlags flags) const
{
    std::vector<Signature *> signatures;
    varbinder::LocalVariable *functionalInterface = CollectSignaturesForSyntheticType(signatures, name, flags);
    // #22952: the called function *always* returns nullptr
    ES2PANDA_ASSERT(functionalInterface == nullptr);
    (void)functionalInterface;

    if (signatures.empty()) {
        return nullptr;
    }

    varbinder::LocalVariable *res = allocator_->New<varbinder::LocalVariable>(varbinder::VariableFlags::SYNTHETIC |
                                                                              varbinder::VariableFlags::METHOD);

    ETSFunctionType *funcType = CreateMethodTypeForProp(name);
    for (auto &s : signatures) {
        funcType->AddCallSignature(s);
    }

    res->SetTsType(funcType);
    funcType->SetVariable(res);

    UpdateDeclarationForGetterSetter(res, funcType, flags);

    return res;
}

ETSFunctionType *ETSObjectType::CreateMethodTypeForProp(const util::StringView &name) const
{
    ES2PANDA_ASSERT(GetRelation() != nullptr);
    return GetRelation()->GetChecker()->AsETSChecker()->CreateETSMethodType(name, {{}, Allocator()->Adapter()});
}

static void AddSignature(std::vector<Signature *> &signatures, PropertySearchFlags flags, ETSChecker *checker,
                         varbinder::LocalVariable *found)
{
    for (auto *it : found->TsType()->AsETSFunctionType()->CallSignatures()) {
        if (std::find(signatures.begin(), signatures.end(), it) != signatures.end()) {
            continue;
        }
        if (((flags & PropertySearchFlags::IGNORE_ABSTRACT) != 0) && it->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            continue;
        }
        if (std::any_of(signatures.begin(), signatures.end(), [&it, &checker](auto sig) {
                return checker->AreOverrideCompatible(sig, it) &&
                       it->Owner()->HasObjectFlag(ETSObjectFlags::INTERFACE) &&
                       (checker->Relation()->IsSupertypeOf(it->Owner(), sig->Owner()) ||
                        !sig->Owner()->HasObjectFlag(ETSObjectFlags::INTERFACE));
            })) {
            continue;
        }
        // Issue: #18720
        // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
        signatures.emplace_back(it);
    }
}

varbinder::LocalVariable *ETSObjectType::CollectSignaturesForSyntheticType(std::vector<Signature *> &signatures,
                                                                           const util::StringView &name,
                                                                           PropertySearchFlags flags) const
{
    auto *checker = GetRelation()->GetChecker()->AsETSChecker();

    if ((flags & PropertySearchFlags::SEARCH_STATIC_METHOD) != 0) {
        if (auto *found = GetOwnProperty<PropertyType::STATIC_METHOD>(name);
            found != nullptr && found->TsType()->IsETSFunctionType()) {
            AddSignature(signatures, flags, checker, found);
        }
    }

    if ((flags & PropertySearchFlags::SEARCH_INSTANCE_METHOD) != 0) {
        if (auto *found = GetOwnProperty<PropertyType::INSTANCE_METHOD>(name);
            found != nullptr && found->TsType()->IsETSFunctionType()) {
            AddSignature(signatures, flags, checker, found);
        }
    }

    if (superType_ != nullptr && ((flags & PropertySearchFlags::SEARCH_IN_BASE) != 0)) {
        superType_->CollectSignaturesForSyntheticType(signatures, name, flags);
    }

    ArenaVector<ETSObjectType *> interfaces(Allocator()->Adapter());
    checker->GetInterfacesOfClass(const_cast<ETSObjectType *>(this), interfaces);

    for (auto *const &interface : interfaces) {
        if (interface != nullptr && ((flags & PropertySearchFlags::SEARCH_IN_INTERFACES) != 0) &&
            !this->IsPartial()) {  // NOTE: issue 24548
            if (auto *found =
                    interface->GetProperty(name, flags | PropertySearchFlags::DISALLOW_SYNTHETIC_METHOD_CREATION);
                found != nullptr && found->TsType()->IsETSFunctionType()) {
                AddSignature(signatures, flags, checker, found);
            }
        }
    }
    return nullptr;
}

std::vector<varbinder::LocalVariable *> ETSObjectType::GetAllProperties() const
{
    std::vector<varbinder::LocalVariable *> allProperties;
    for (const auto &[_, prop] : InstanceFields()) {
        (void)_;
        allProperties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticFields()) {
        (void)_;
        allProperties.push_back(prop);
    }

    for (const auto &[_, prop] : InstanceMethods()) {
        (void)_;
        allProperties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticMethods()) {
        (void)_;
        allProperties.push_back(prop);
    }

    for (const auto &[_, prop] : InstanceDecls()) {
        (void)_;
        allProperties.push_back(prop);
    }

    for (const auto &[_, prop] : StaticDecls()) {
        (void)_;
        allProperties.push_back(prop);
    }

    return allProperties;
}

std::vector<varbinder::LocalVariable *> ETSObjectType::Methods() const
{
    std::vector<varbinder::LocalVariable *> methods;
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

std::vector<varbinder::LocalVariable *> ETSObjectType::Fields() const
{
    std::vector<varbinder::LocalVariable *> fields;
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

std::vector<const varbinder::LocalVariable *> ETSObjectType::ForeignProperties() const
{
    std::vector<const varbinder::LocalVariable *> foreignProps;

    // spec 9.3: all names in static and, separately, non-static class declaration scopes must be unique.
    std::unordered_set<util::StringView> ownInstanceProps;
    std::unordered_set<util::StringView> ownStaticProps;

    EnsurePropertiesInstantiated();
    ownInstanceProps.reserve(properties_.size());
    ownStaticProps.reserve(properties_.size());

    for (const auto *prop : GetAllProperties()) {
        if (prop->HasFlag(varbinder::VariableFlags::STATIC)) {
            ownStaticProps.insert(prop->Name());
        } else {
            ownInstanceProps.insert(prop->Name());
        }
    }

    std::map<util::StringView, const varbinder::LocalVariable *> allInstanceProps {};
    std::map<util::StringView, const varbinder::LocalVariable *> allStaticProps {};
    Iterate([&allInstanceProps, &allStaticProps](const varbinder::LocalVariable *var) {
        if (var->HasFlag(varbinder::VariableFlags::STATIC)) {
            allStaticProps.emplace(var->Name(), var);
        } else {
            allInstanceProps.emplace(var->Name(), var);
        }
    });

    for (const auto &[name, var] : allInstanceProps) {
        if (ownInstanceProps.find(name) == ownInstanceProps.end()) {
            foreignProps.push_back(var);
        }
    }
    for (const auto &[name, var] : allStaticProps) {
        if (ownStaticProps.find(name) == ownStaticProps.end()) {
            foreignProps.push_back(var);
        }
    }

    return foreignProps;
}

void ETSObjectType::ToString(std::stringstream &ss, bool precise) const
{
    if (IsPartial()) {
        ss << "Partial" << compiler::Signatures::GENERIC_BEGIN;
        baseType_->ToString(ss, precise);
        ss << compiler::Signatures::GENERIC_END;
        return;
    }

    if (HasTypeFlag(TypeFlag::READONLY)) {
        ss << "Readonly" << compiler::Signatures::GENERIC_BEGIN;
    }
    if (HasObjectFlag(ETSObjectFlags::REQUIRED)) {
        ss << "Required" << compiler::Signatures::GENERIC_BEGIN;
    }

    ss << (precise ? internalName_ : name_);

    if (!typeArguments_.empty()) {
        ss << compiler::Signatures::GENERIC_BEGIN;
        for (auto arg = typeArguments_.cbegin(); arg != typeArguments_.cend(); ++arg) {
            (*arg)->ToString(ss, precise);

            if (next(arg) != typeArguments_.cend()) {
                ss << lexer::TokenToString(lexer::TokenType::PUNCTUATOR_COMMA);
            }
        }
        ss << compiler::Signatures::GENERIC_END;
    }

    if (HasObjectFlag(ETSObjectFlags::REQUIRED)) {
        ss << compiler::Signatures::GENERIC_END;
    }
    if (HasTypeFlag(TypeFlag::READONLY)) {
        ss << compiler::Signatures::GENERIC_END;
    }
}

void ETSObjectType::SubstitutePartialTypes(TypeRelation *relation, Type *other)
{
    ES2PANDA_ASSERT(IsPartial());

    if ((baseType_->IsGeneric() || baseType_->IsETSTypeParameter()) && effectiveSubstitution_ != nullptr) {
        if (auto *newBaseType = baseType_->Substitute(relation, effectiveSubstitution_);
            newBaseType->IsETSObjectType() && !relation->IsIdenticalTo(newBaseType, baseType_)) {
            baseType_ = newBaseType->AsETSObjectType();
        }
    }

    if (other->IsETSObjectType() && other->AsETSObjectType()->IsPartial()) {
        auto *otherPartial = other->AsETSObjectType();
        if ((otherPartial->baseType_->IsGeneric() || otherPartial->baseType_->IsETSTypeParameter()) &&
            otherPartial->effectiveSubstitution_ != nullptr) {
            if (auto *newBaseType = otherPartial->baseType_->Substitute(relation, otherPartial->effectiveSubstitution_);
                newBaseType->IsETSObjectType() && !relation->IsIdenticalTo(newBaseType, otherPartial->baseType_)) {
                otherPartial->baseType_ = newBaseType->AsETSObjectType();
            }
        }
    }
    relation->Result(false);  // this function spoils the relation
}

void ETSObjectType::IdenticalUptoTypeArguments(TypeRelation *relation, Type *other)
{
    relation->Result(false);

    if (IsPartial()) {
        SubstitutePartialTypes(relation, other);
    }

    if (!other->IsETSObjectType() || !CheckIdenticalFlags(other->AsETSObjectType())) {
        return;
    }

    // NOTE: (DZ) only both Partial types can be compatible.
    if (static_cast<bool>(static_cast<std::byte>(IsPartial()) ^
                          static_cast<std::byte>(other->AsETSObjectType()->IsPartial()))) {
        return;
    }

    auto *thisBase = GetOriginalBaseType();
    auto *otherBase = other->AsETSObjectType()->GetOriginalBaseType();
    if (thisBase->Variable() != otherBase->Variable()) {
        return;
    }

    if ((relation->IgnoreTypeParameters() && !HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) || (this == other)) {
        relation->Result(true);
        return;
    }

    auto const sourceTypeArguments = other->AsETSObjectType()->TypeArguments();
    if (typeArguments_.empty() != sourceTypeArguments.empty()) {
        return;
    }

    relation->Result(true);
}

void ETSObjectType::Identical(TypeRelation *relation, Type *other)
{
    IdenticalUptoTypeArguments(relation, other);

    if (!relation->IsTrue() || !HasTypeFlag(TypeFlag::GENERIC) || !other->IsETSObjectType()) {
        return;
    }

    if (HasTypeFlag(TypeFlag::READONLY) != other->HasTypeFlag(TypeFlag::READONLY)) {
        relation->Result(false);
        return;
    }

    auto const otherTypeArguments = other->AsETSObjectType()->TypeArguments();

    auto const argsNumber = typeArguments_.size();
    if (argsNumber != otherTypeArguments.size()) {
        relation->Result(false);
        return;
    }

    for (size_t idx = 0U; idx < argsNumber; ++idx) {
        if (typeArguments_[idx]->IsWildcardType() || otherTypeArguments[idx]->IsWildcardType()) {
            continue;
        }
        if (!relation->IsIdenticalTo(typeArguments_[idx], otherTypeArguments[idx])) {
            return;
        }
    }

    relation->Result(true);
}

bool ETSObjectType::CheckIdenticalFlags(ETSObjectType *other) const
{
    constexpr auto FLAGS_TO_REMOVE = ETSObjectFlags::INCOMPLETE_INSTANTIATION |
                                     ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS |
                                     ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY | ETSObjectFlags::EXTENSION_FUNCTION;

    auto cleanedTargetFlags = other->ObjectFlags();
    cleanedTargetFlags &= ~FLAGS_TO_REMOVE;

    auto cleanedSelfFlags = ObjectFlags();
    cleanedSelfFlags &= ~FLAGS_TO_REMOVE;

    return cleanedSelfFlags == cleanedTargetFlags;
}

bool ETSObjectType::AssignmentSource(TypeRelation *const relation, [[maybe_unused]] Type *const target)
{
    // NOTE: do not modify, to be implied by the relation
    return relation->IsSupertypeOf(target, this);
}

bool ETSObjectType::IsBoxedPrimitive() const
{
    if (this->IsETSDynamicType()) {
        return false;
    }

    return this->IsETSUnboxableObject();
}

void ETSObjectType::AssignmentTarget(TypeRelation *const relation, Type *source)
{
    // NOTE: do not modify, to be implied by the relation
    relation->IsSupertypeOf(this, source);
}

ETSFunctionType *ETSObjectType::GetFunctionalInterfaceInvokeType() const
{
    ES2PANDA_ASSERT(HasObjectFlag(ETSObjectFlags::FUNCTIONAL));

    // NOTE(vpukhov): this is still better than to retain any "functional" state in ETSObjectType
    auto [foundArity, hasRest] = [this]() {
        auto checker = GetRelation()->GetChecker()->AsETSChecker();
        auto baseType = GetConstOriginalBaseType();
        for (size_t arity = 0; arity < checker->GetGlobalTypesHolder()->VariadicFunctionTypeThreshold(); ++arity) {
            if (auto itf = checker->GlobalBuiltinFunctionType(arity, false); itf == baseType) {
                return std::make_pair(arity, false);
            }
            if (auto itf = checker->GlobalBuiltinFunctionType(arity, true); itf == baseType) {
                return std::make_pair(arity, true);
            }
        }
        ES2PANDA_UNREACHABLE();
    }();

    std::string invokeName = FunctionalInterfaceInvokeName(foundArity, hasRest);
    auto *invoke = GetOwnProperty<PropertyType::INSTANCE_METHOD>(util::StringView(invokeName));
    ES2PANDA_ASSERT(invoke != nullptr && invoke->TsType() != nullptr && invoke->TsType()->IsETSFunctionType());
    return invoke->TsType()->AsETSFunctionType();
}

bool ETSObjectType::CastWideningNarrowing(TypeRelation *const relation, Type *const target, TypeFlag unboxFlags,
                                          TypeFlag wideningFlags, TypeFlag narrowingFlags)
{
    if (target->HasTypeFlag(unboxFlags)) {
        conversion::Unboxing(relation, this);
        return true;
    }
    if (target->HasTypeFlag(wideningFlags)) {
        conversion::UnboxingWideningPrimitive(relation, this, target);
        return true;
    }
    if (target->HasTypeFlag(narrowingFlags)) {
        conversion::UnboxingNarrowingPrimitive(relation, this, target);
        return true;
    }
    return false;
}

bool ETSObjectType::TryCastByte(TypeRelation *const relation, Type *const target)
{
    if (target->HasTypeFlag(TypeFlag::BYTE)) {
        conversion::Unboxing(relation, this);
        return true;
    }
    if (target->HasTypeFlag(TypeFlag::SHORT | TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE)) {
        conversion::UnboxingWideningPrimitive(relation, this, target);
        return true;
    }
    if (target->HasTypeFlag(TypeFlag::CHAR)) {
        conversion::UnboxingWideningNarrowingPrimitive(relation, this, target);
        return true;
    }
    return false;
}

bool ETSObjectType::TryCastIntegral(TypeRelation *const relation, Type *const target)
{
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_BYTE) && TryCastByte(relation, target)) {
        return true;
    }
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_SHORT) &&
        CastWideningNarrowing(relation, target, TypeFlag::SHORT,
                              TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE,
                              TypeFlag::BYTE | TypeFlag::CHAR)) {
        return true;
    }
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR) &&
        CastWideningNarrowing(relation, target, TypeFlag::CHAR,
                              TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE,
                              TypeFlag::BYTE | TypeFlag::SHORT)) {
        return true;
    }
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_INT) &&
        CastWideningNarrowing(relation, target, TypeFlag::INT, TypeFlag::LONG | TypeFlag::FLOAT | TypeFlag::DOUBLE,
                              TypeFlag::BYTE | TypeFlag::SHORT | TypeFlag::CHAR)) {
        return true;
    }
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_LONG) &&
        CastWideningNarrowing(relation, target, TypeFlag::LONG, TypeFlag::FLOAT | TypeFlag::DOUBLE,
                              TypeFlag::BYTE | TypeFlag::SHORT | TypeFlag::CHAR | TypeFlag::INT)) {
        return true;
    }
    return false;
}

bool ETSObjectType::TryCastFloating(TypeRelation *const relation, Type *const target)
{
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_FLOAT) &&
        CastWideningNarrowing(relation, target, TypeFlag::FLOAT, TypeFlag::DOUBLE,
                              TypeFlag::BYTE | TypeFlag::SHORT | TypeFlag::CHAR | TypeFlag::INT | TypeFlag::LONG)) {
        return true;
    }
    if (auto narrowingFlags =
            TypeFlag::BYTE | TypeFlag::SHORT | TypeFlag::CHAR | TypeFlag::INT | TypeFlag::LONG | TypeFlag::FLOAT;
        this->HasObjectFlag(ETSObjectFlags::BUILTIN_DOUBLE) &&
        CastWideningNarrowing(relation, target, TypeFlag::DOUBLE, TypeFlag::NONE, narrowingFlags)) {
        return true;
    }
    return false;
}

bool ETSObjectType::TryCastUnboxable(TypeRelation *const relation, Type *const target)
{
    if (target->HasTypeFlag(TypeFlag::ETS_OBJECT)) {
        if (!target->IsETSUnboxableObject()) {
            conversion::WideningReference(relation, this, target->AsETSObjectType());
            return true;
        }
        auto unboxedTarget = relation->GetChecker()->AsETSChecker()->MaybeUnboxInRelation(target);
        CastNumericObject(relation, unboxedTarget);
        if (relation->IsTrue()) {
            conversion::Boxing(relation, unboxedTarget);
            return true;
        }
        conversion::WideningReference(relation, this, target->AsETSObjectType());
        return true;
    }
    conversion::Forbidden(relation);
    return true;
}

bool ETSObjectType::CastNumericObject(TypeRelation *const relation, Type *const target)
{
    if (!target->IsETSPrimitiveType()) {
        return false;
    }
    if (relation->IsIdenticalTo(this, target)) {
        return true;
    }
    if (TryCastIntegral(relation, target)) {
        return true;
    }
    if (TryCastFloating(relation, target)) {
        return true;
    }
    if (this->HasObjectFlag(ETSObjectFlags::BUILTIN_BOOLEAN) && target->HasTypeFlag(TypeFlag::ETS_BOOLEAN)) {
        conversion::Unboxing(relation, this);
        return true;
    }
    if (this->IsETSUnboxableObject()) {
        return TryCastUnboxable(relation, target);
    }
    if (target->IsETSPrimitiveType()) {
        conversion::NarrowingReferenceUnboxing(relation, this, target);
        return true;
    }
    return false;
}

void ETSObjectType::Cast(TypeRelation *const relation, Type *const target)
{
    conversion::Identity(relation, this, target);
    if (relation->IsTrue()) {
        return;
    }

    if (CastNumericObject(relation, target)) {
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_ARRAY)) {
        conversion::NarrowingReference(relation, this, target->AsETSArrayType());
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_TUPLE)) {
        conversion::NarrowingReference(relation, this, target->AsETSTupleType());
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

    //  #16485: Probably temporary solution for generic bridges realization. Allows casting of generic classes
    //          in the form C<T> as C<U> (where U extends T) or C<T> as D (where D extends C<U>)
    if ((relation->GetChecker()->Context().Status() & CheckerStatus::IN_BRIDGE_TEST) != 0U) {
        SavedTypeRelationFlagsContext const savedFlags(relation, relation->GetTypeRelationFlags() |
                                                                     TypeRelationFlag::IGNORE_TYPE_PARAMETERS);
        relation->IsSupertypeOf(this, target);
        return;
    }

    conversion::Forbidden(relation);
}

void ETSObjectType::IsSupertypeOf(TypeRelation *relation, Type *source)
{
    relation->Result(false);
    auto const checker = relation->GetChecker()->AsETSChecker();

    if (source->HasTypeFlag(TypeFlag::READONLY)) {
        relation->Result(false);
        return;
    }
    if (IsPartial()) {
        source->IsETSObjectType() && source->AsETSObjectType()->IsPartial() &&
            relation->IsSupertypeOf(GetBaseType(), source->AsETSObjectType()->GetBaseType());
        return;
    }
    if (!source->IsETSObjectType()) {
        return;
    }

    auto const sourceObj = source->AsETSObjectType();
    // #23072 - superType_ of the current object is not intialized in recursive generics
    if (GetConstOriginalBaseType() == checker->GlobalETSObjectType()) {  // Fastpath, all objects are subtypes of Object
        relation->Result(true);
        return;
    }
    if (sourceObj->HasObjectFlag(ETSObjectFlags::CLASS | ETSObjectFlags::INTERFACE)) {
        IdenticalUptoTypeArguments(relation, sourceObj);
        if (relation->IsTrue() && HasTypeFlag(TypeFlag::GENERIC) && !relation->IgnoreTypeParameters()) {
            IsGenericSupertypeOf(relation, sourceObj);
        }
        if (relation->IsTrue()) {
            return;
        }
    }
    //  #16485: special case for generic bridges processing.
    //          We need only to check if the type is immediate supertype of processing class.
    if ((checker->Context().Status() & CheckerStatus::IN_BRIDGE_TEST) != 0U && relation->IsBridgeCheck()) {
        if (sourceObj->Variable() == checker->Context().ContainingClass()->SuperType()->Variable()) {
            return;
        }
    }
}

void ETSObjectType::IsSubtypeOf(TypeRelation *relation, Type *target)
{
    if (auto super = SuperType(); super != nullptr) {
        if (relation->IsSupertypeOf(target, super)) {
            return;
        }
    }
    for (auto super : Interfaces()) {
        if (relation->IsSupertypeOf(target, super)) {
            return;
        }
    }
}

void ETSObjectType::IsGenericSupertypeOf(TypeRelation *relation, ETSObjectType *source)
{
    ES2PANDA_ASSERT(HasTypeFlag(TypeFlag::GENERIC));

    auto const &sourceTypeArguments = source->TypeArguments();
    auto const typeArgumentsNumber = typeArguments_.size();
    if (typeArgumentsNumber > sourceTypeArguments.size()) {
        relation->Result(false);
        return;
    }

    ES2PANDA_ASSERT(declNode_ == source->GetDeclNode());

    auto *typeParamsDecl = GetTypeParams();
    ES2PANDA_ASSERT(typeParamsDecl != nullptr || typeArguments_.empty());

    if (typeParamsDecl == nullptr) {
        return;
    }

    auto &typeParams = typeParamsDecl->Params();
    ES2PANDA_ASSERT(typeParams.size() == typeArgumentsNumber);

    for (size_t idx = 0U; idx < typeArgumentsNumber; ++idx) {
        auto *typeArg = typeArguments_[idx];
        auto *sourceTypeArg = sourceTypeArguments[idx];
        auto *typeParam = typeParams[idx];

        relation->Result(false);
        if (typeArg->IsWildcardType() || sourceTypeArg->IsWildcardType()) {
            continue;
        }
        if (typeParam->IsOut()) {
            relation->IsSupertypeOf(typeArg, sourceTypeArg);
        } else if (typeParam->IsIn()) {
            relation->IsSupertypeOf(sourceTypeArg, typeArg);
        } else {
            relation->IsIdenticalTo(typeArg, sourceTypeArg);
        }

        if (!relation->IsTrue()) {
            return;
        }
    }

    relation->Result(true);
}

Type *ETSObjectType::AsSuper(Checker *checker, varbinder::Variable *sourceVar)
{
    if (sourceVar == nullptr) {
        return nullptr;
    }

    if (variable_ == sourceVar) {
        return this;
    }

    if (HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        Type *res = nullptr;
        for (auto *const it : checker->AsETSChecker()->GetInterfaces(this)) {
            res = it->AsSuper(checker, sourceVar);
            if (res != nullptr) {
                return res;
            }
        }
        return checker->GetGlobalTypesHolder()->GlobalETSObjectType()->AsSuper(checker, sourceVar);
    }

    Type *const superType = checker->AsETSChecker()->GetSuperType(this);

    if (superType == nullptr) {
        return nullptr;
    }

    if (!superType->IsETSObjectType()) {
        return nullptr;
    }

    if (ETSObjectType *const superObj = superType->AsETSObjectType(); superObj->HasObjectFlag(ETSObjectFlags::CLASS)) {
        Type *const res = superObj->AsSuper(checker, sourceVar);
        if (res != nullptr) {
            return res;
        }
    }

    if (sourceVar->TsType()->IsETSObjectType() &&
        sourceVar->TsType()->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
        for (auto *const it : checker->AsETSChecker()->GetInterfaces(this)) {
            Type *const res = it->AsSuper(checker, sourceVar);
            if (res != nullptr) {
                return res;
            }
        }
    }

    return nullptr;
}

varbinder::LocalVariable *ETSObjectType::CopyProperty(varbinder::LocalVariable *prop, ArenaAllocator *allocator,
                                                      TypeRelation *relation, GlobalTypesHolder *globalTypes)
{
    auto *const copiedProp = prop->Copy(allocator, prop->Declaration());
    auto *const copiedPropType = ETSChecker::TryToInstantiate(
        relation->GetChecker()->AsETSChecker()->GetTypeOfVariable(prop), allocator, relation, globalTypes);
    // NOTE: don't change type variable if it differs from copying one!
    if (copiedPropType->Variable() == prop) {
        copiedPropType->SetVariable(copiedProp);
    }
    copiedProp->SetTsType(copiedPropType);
    return copiedProp;
}

Type *ETSObjectType::Instantiate(ArenaAllocator *const allocator, TypeRelation *const relation,
                                 GlobalTypesHolder *const globalTypes)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    std::lock_guard guard {*checker->Mutex()};
    auto *const base = GetOriginalBaseType();

    if (!relation->IsAtTypeDepthLimit(base)) {
        return this;
    }
    relation->IncreaseTypeRecursionCount(base);

    auto *const copiedType = checker->CreateETSObjectType(declNode_, flags_);
    ES2PANDA_ASSERT(copiedType->internalName_ == internalName_);
    ES2PANDA_ASSERT(copiedType->name_ == name_);
    copiedType->typeFlags_ = typeFlags_;
    copiedType->RemoveObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS |
                                 ETSObjectFlags::INCOMPLETE_INSTANTIATION | ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
    copiedType->SetVariable(variable_);
    copiedType->SetSuperType(superType_);

    for (auto *const it : interfaces_) {
        copiedType->AddInterface(it);
    }

    ArenaVector<Type *> typeArgs(allocator->Adapter());
    for (auto *const typeArgument : TypeArguments()) {
        typeArgs.emplace_back(typeArgument->Instantiate(allocator, relation, globalTypes));
    }
    copiedType->SetTypeArguments(std::move(typeArgs));
    copiedType->SetBaseType(this);
    copiedType->propertiesInstantiated_ = false;
    copiedType->relation_ = relation;
    copiedType->effectiveSubstitution_ = nullptr;

    relation->DecreaseTypeRecursionCount(base);

    return copiedType;
}

static Type *SubstituteVariableType(TypeRelation *relation, const Substitution *substitution, Type *const varType)
{
    auto *substitutedType = varType->Substitute(relation, substitution);

    if (varType->HasTypeFlag(TypeFlag::ETS_REQUIRED_TYPE_PARAMETER)) {
        substitutedType = relation->GetChecker()->AsETSChecker()->HandleRequiredType(substitutedType);
    }

    return substitutedType;
}

static varbinder::LocalVariable *CopyPropertyWithTypeArguments(varbinder::LocalVariable *prop, TypeRelation *relation,
                                                               const Substitution *substitution)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *const varType = ETSChecker::IsVariableGetterSetter(prop) ? prop->TsType() : checker->GetTypeOfVariable(prop);
    auto *const copiedPropType = SubstituteVariableType(relation, substitution, varType);
    auto *const copiedProp = prop->Copy(checker->Allocator(), prop->Declaration());
    // NOTE: some situation copiedPropType we get here are types cached in Checker,
    // uncontrolled SetVariable will pollute the cache.
    if (copiedPropType->Variable() == prop || copiedPropType->Variable() == nullptr) {
        copiedPropType->SetVariable(copiedProp);
    }
    copiedProp->SetTsType(copiedPropType);
    return copiedProp;
}

ETSObjectType const *ETSObjectType::GetConstOriginalBaseType() const noexcept
{
    if (auto *baseIter = GetBaseType(); baseIter != nullptr) {
        auto *baseIterNext = baseIter->GetBaseType();
        while (baseIterNext != nullptr && baseIterNext != baseIter) {
            baseIter = baseIterNext;
            baseIterNext = baseIter->GetBaseType();
        }
        return baseIter;
    }
    return this;
}

bool ETSObjectType::SubstituteTypeArgs(TypeRelation *const relation, ArenaVector<Type *> &newTypeArgs,
                                       const Substitution *const substitution)
{
    bool anyChange = false;
    newTypeArgs.reserve(typeArguments_.size());

    for (auto *const arg : typeArguments_) {
        auto *const newArg = arg->Substitute(relation, substitution);
        newTypeArgs.push_back(newArg);
        anyChange = anyChange || (newArg != arg);
    }

    return anyChange;
}

static Substitution *ComputeEffectiveSubstitution(TypeRelation *const relation,
                                                  const ArenaVector<Type *> &baseTypeParams,
                                                  ArenaVector<Type *> &newTypeArgs)
{
    ES2PANDA_ASSERT(baseTypeParams.size() == newTypeArgs.size());
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *effectiveSubstitution = checker->NewSubstitution();

    for (size_t ix = 0; ix < baseTypeParams.size(); ix++) {
        checker->EmplaceSubstituted(effectiveSubstitution, baseTypeParams[ix]->AsETSTypeParameter(), newTypeArgs[ix]);
    }

    return effectiveSubstitution;
}

void ETSObjectType::SetCopiedTypeProperties(TypeRelation *const relation, ETSObjectType *const copiedType,
                                            ArenaVector<Type *> &&newTypeArgs, ETSObjectType *base)
{
    copiedType->typeFlags_ = typeFlags_;
    copiedType->RemoveObjectFlag(ETSObjectFlags::CHECKED_COMPATIBLE_ABSTRACTS |
                                 ETSObjectFlags::INCOMPLETE_INSTANTIATION | ETSObjectFlags::CHECKED_INVOKE_LEGITIMACY);
    copiedType->SetVariable(variable_);
    copiedType->SetBaseType(base);

    auto const &baseTypeParams = base->TypeArguments();
    copiedType->effectiveSubstitution_ = ComputeEffectiveSubstitution(relation, baseTypeParams, newTypeArgs);

    copiedType->SetTypeArguments(std::move(newTypeArgs));
    copiedType->relation_ = relation;
}

void ETSObjectType::UpdateTypeProperty(checker::ETSChecker *checker, varbinder::LocalVariable *const prop,
                                       PropertyType fieldType, PropertyProcesser const &func)
{
    auto const propType = prop->Declaration()->Node()->Check(checker);

    auto *const propCopy = func(prop, propType);
    if (fieldType == PropertyType::INSTANCE_FIELD) {
        RemoveProperty<PropertyType::INSTANCE_FIELD>(prop);
        AddProperty<PropertyType::INSTANCE_FIELD>(propCopy);
    } else {
        RemoveProperty<PropertyType::STATIC_FIELD>(prop);
        AddProperty<PropertyType::STATIC_FIELD>(propCopy);
    }
}

void ETSObjectType::UpdateTypeProperties(checker::ETSChecker *checker, PropertyProcesser const &func)
{
    AddTypeFlag(TypeFlag::READONLY);
    for (auto const &prop : InstanceFields()) {
        UpdateTypeProperty(checker, prop.second, PropertyType::INSTANCE_FIELD, func);
    }

    for (auto const &prop : StaticFields()) {
        UpdateTypeProperty(checker, prop.second, PropertyType::STATIC_FIELD, func);
    }

    if (SuperType() != nullptr) {
        auto *const superProp = SuperType()->Clone(checker)->AsETSObjectType();
        superProp->UpdateTypeProperties(checker, func);
        SetSuperType(superProp);
    }
}

// #22951: remove isExtensionFunctionType flag
ETSObjectType *ETSObjectType::Substitute(TypeRelation *relation, const Substitution *substitution, bool cache,
                                         bool isExtensionFunctionType)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }

    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *base = GetOriginalBaseType();

    ArenaVector<Type *> newTypeArgs {checker->Allocator()->Adapter()};
    const bool anyChange = SubstituteTypeArgs(relation, newTypeArgs, substitution);
    // Lambda types can capture type params in their bodies, normal classes cannot.
    // NOTE: gogabr. determine precise conditions where we do not need to copy.
    // Perhaps keep track of captured type parameters for each type.
    if (!anyChange && !HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        return this;
    }

    const util::StringView hash = checker->GetHashFromSubstitution(substitution, isExtensionFunctionType);
    if (cache) {
        if (auto *inst = GetInstantiatedType(hash); inst != nullptr) {
            return inst;
        }
    }

    if (!relation->IsAtTypeDepthLimit(base)) {
        return this;
    }
    relation->IncreaseTypeRecursionCount(base);

    auto *const copiedType = checker->CreateETSObjectType(declNode_, flags_);
    SetCopiedTypeProperties(relation, copiedType, std::move(newTypeArgs), base);
    if (isExtensionFunctionType) {
        copiedType->AddObjectFlag(checker::ETSObjectFlags::EXTENSION_FUNCTION);
    }

    if (cache) {
        GetInstantiationMap().try_emplace(hash, copiedType);
    }

    if (superType_ != nullptr) {
        copiedType->SetSuperType(superType_->Substitute(relation, substitution)->AsETSObjectType());
    }
    for (auto *itf : interfaces_) {
        auto *newItf = itf->Substitute(relation, substitution)->AsETSObjectType();
        copiedType->AddInterface(newItf);
    }

    relation->DecreaseTypeRecursionCount(base);

    return copiedType;
}

ETSObjectType *ETSObjectType::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    return Substitute(relation, substitution, true);
}

ETSObjectType *ETSObjectType::SubstituteArguments(TypeRelation *relation, ArenaVector<Type *> const &arguments)
{
    if (arguments.empty()) {
        return this;
    }

    auto *checker = relation->GetChecker()->AsETSChecker();
    auto *substitution = checker->NewSubstitution();

    ES2PANDA_ASSERT(baseType_ == nullptr);
    ES2PANDA_ASSERT(typeArguments_.size() == arguments.size());

    for (size_t ix = 0; ix < typeArguments_.size(); ix++) {
        substitution->emplace(typeArguments_[ix]->AsETSTypeParameter(), checker->MaybeBoxType(arguments[ix]));
    }

    return Substitute(relation, substitution);
}

void ETSObjectType::InstantiateProperties() const
{
    ES2PANDA_ASSERT(relation_ != nullptr);
    auto *checker = relation_->GetChecker()->AsETSChecker();

    if (baseType_ == nullptr || baseType_ == this) {
        checker->ResolveDeclaredMembersOfObject(this);
        return;
    }

    ES2PANDA_ASSERT(!propertiesInstantiated_);
    declNode_->Check(checker);

    for (auto *const it : baseType_->ConstructSignatures()) {
        auto *newSig = it->Substitute(relation_, effectiveSubstitution_);
        constructSignatures_.push_back(newSig);
    }

    for (auto const &[_, prop] : baseType_->InstanceFields()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_FIELD)].emplace(prop->Name(), copiedProp);
    }

    for (auto const &[_, prop] : baseType_->StaticFields()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_FIELD)].emplace(prop->Name(), copiedProp);
    }

    for (auto const &[_, prop] : baseType_->InstanceMethods()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_METHOD)].emplace(prop->Name(), copiedProp);
    }

    for (auto const &[_, prop] : baseType_->StaticMethods()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_METHOD)].emplace(prop->Name(), copiedProp);
    }

    for (auto const &[_, prop] : baseType_->InstanceDecls()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::INSTANCE_DECL)].emplace(prop->Name(), copiedProp);
    }

    for (auto const &[_, prop] : baseType_->StaticDecls()) {
        (void)_;
        auto *copiedProp = CopyPropertyWithTypeArguments(prop, relation_, effectiveSubstitution_);
        properties_[static_cast<size_t>(PropertyType::STATIC_DECL)].emplace(prop->Name(), copiedProp);
    }
}

std::string ETSObjectType::NameToDescriptor(util::StringView name)
{
    auto desc = std::string(compiler::Signatures::CLASS_REF_BEGIN)
                    .append(name.Utf8())
                    .append(std::string(compiler::Signatures::MANGLE_SEPARATOR));
    std::replace(desc.begin(), desc.end(), *compiler::Signatures::METHOD_SEPARATOR.begin(),
                 *compiler::Signatures::NAMESPACE_SEPARATOR.begin());
    return desc;
}

std::uint32_t ETSObjectType::GetPrecedence(checker::ETSChecker *checker, ETSObjectType const *type) noexcept
{
    ES2PANDA_ASSERT(type != nullptr);
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_BYTE)) {
        return 1U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_CHAR)) {
        return 2U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_SHORT)) {
        return 3U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_INT)) {
        return 4U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_LONG)) {
        return 5U;
    }
    if (checker->Relation()->IsIdenticalTo(const_cast<ETSObjectType *>(type),
                                           checker->GetGlobalTypesHolder()->GlobalIntegralBuiltinType())) {
        return 5U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_FLOAT)) {
        return 6U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_DOUBLE)) {
        return 7U;
    }
    if (checker->Relation()->IsIdenticalTo(const_cast<ETSObjectType *>(type),
                                           checker->GetGlobalTypesHolder()->GlobalFloatingBuiltinType())) {
        return 7U;
    }
    if (type->HasObjectFlag(ETSObjectFlags::BUILTIN_BIGINT)) {
        return 8U;
    }
    return 0U;
}
void ETSObjectType::AddReExports(ETSObjectType *reExport)
{
    if (std::find(reExports_.begin(), reExports_.end(), reExport) == reExports_.end()) {
        reExports_.push_back(reExport);
    }
}

void ETSObjectType::AddReExportAlias(util::StringView const &value, util::StringView const &key)
{
    reExportAlias_.insert({key, value});
}

util::StringView ETSObjectType::GetReExportAliasValue(util::StringView const &key) const
{
    auto ret = reExportAlias_.find(key);
    if (reExportAlias_.end() == ret) {
        return key;
    }
    return ret->second;
}

bool ETSObjectType::IsReExportHaveAliasValue(util::StringView const &key) const
{
    return std::any_of(reExportAlias_.begin(), reExportAlias_.end(),
                       [&](const auto &val) { return val.second == key; });
}

const ArenaVector<ETSObjectType *> &ETSObjectType::ReExports() const
{
    return reExports_;
}

void ETSObjectType::ToAssemblerType([[maybe_unused]] std::stringstream &ss) const
{
    ss << internalName_;
}

void ETSObjectType::ToDebugInfoType(std::stringstream &ss) const
{
    ss << NameToDescriptor(internalName_);
}

void ETSObjectType::ToDebugInfoSignatureType(std::stringstream &ss) const
{
    ss << compiler::Signatures::GENERIC_BEGIN;
    ss << internalName_;
    ss << compiler::Signatures::GENERIC_END;
}

ir::TSTypeParameterDeclaration *ETSObjectType::GetTypeParams() const
{
    if (HasObjectFlag(ETSObjectFlags::ENUM) || !HasTypeFlag(TypeFlag::GENERIC)) {
        return nullptr;
    }

    if (HasObjectFlag(ETSObjectFlags::CLASS)) {
        ES2PANDA_ASSERT(declNode_->IsClassDefinition() && declNode_->AsClassDefinition()->TypeParams());
        return declNode_->AsClassDefinition()->TypeParams();
    }

    ES2PANDA_ASSERT(declNode_->IsTSInterfaceDeclaration() && declNode_->AsTSInterfaceDeclaration()->TypeParams());
    return declNode_->AsTSInterfaceDeclaration()->TypeParams();
}

bool ETSObjectType::IsSameBasedGeneric(TypeRelation *relation, Type const *other) const
{
    const_cast<ETSObjectType *>(this)->IdenticalUptoTypeArguments(relation, const_cast<Type *>(other));
    return relation->IsTrue();
}

void ETSObjectType::CheckVarianceRecursively(TypeRelation *relation, VarianceFlag varianceFlag)
{
    if (HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        relation->CheckVarianceRecursively(GetFunctionalInterfaceInvokeType(), varianceFlag);
        return;
    }

    // according to the spec(GENERICS chapter), only class/interface/function/
    // method/lambda and type alias can have type parameters. since
    // 1. the type of function and method is ETSFunctionType
    // 2. lambda has been checked above
    // here we just need check
    // 1. class
    // 2. interface
    // 3. type alias(which will be redirected to its real type)
    // And all of them should have declarations
    if (declNode_ == nullptr) {
        // If the type is not declared, then we do not need to check variance.
        return;
    }
    ir::TSTypeParameterDeclaration *params;
    if (GetDeclNode()->IsClassDefinition()) {
        params = GetDeclNode()->AsClassDefinition()->TypeParams();
    } else if (GetDeclNode()->IsTSInterfaceDeclaration()) {
        params = GetDeclNode()->AsTSInterfaceDeclaration()->TypeParams();
    } else {
        // If the type is not a class or interface or type alias, then we do not need to check variance.
        return;
    }

    if (params == nullptr) {
        return;
    }

    auto typeArgs = TypeArguments();
    for (size_t i = 0; i < typeArgs.size(); ++i) {
        // If the Variance of type Args is the same as the Variance of type params, then the class is Covariant.
        // If the Variance of type Args is the opposite of the Variance of type params, then the class is
        // Contravariant.
        auto param = params->Params().at(i);
        relation->CheckVarianceRecursively(
            typeArgs.at(i), relation->TransferVariant(varianceFlag, param->IsIn()    ? VarianceFlag::CONTRAVARIANT
                                                                    : param->IsOut() ? VarianceFlag::COVARIANT
                                                                                     : VarianceFlag::INVARIANT));
    }
}

}  // namespace ark::es2panda::checker
