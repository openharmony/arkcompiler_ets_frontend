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

#include "etsEnumType.h"

#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/ets/unboxingConverter.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/ts/tsEnumMember.h"

namespace ark::es2panda::checker {
ETSEnumType::ETSEnumType(const ir::TSEnumDeclaration *const enumDecl, UType ordinal,
                         const ir::TSEnumMember *const member, TypeFlag const typeFlag)
    : Type(typeFlag), decl_(enumDecl), ordinal_ {ordinal}, member_(member)
{
}

bool ETSEnumType::AssignmentSource(TypeRelation *const relation, Type *const target)
{
    bool result = false;

    if (target->IsETSEnumType()) {
        result = IsSameEnumType(target->AsETSEnumType());
    } else if (target->IsETSStringType()) {
        result = IsETSStringEnumType();
        if (result) {
            relation->GetNode()->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
        }
    } else if (target->IsETSObjectType()) {
        if (target->AsETSObjectType()->IsGlobalETSObjectType()) {
            result = true;
            relation->GetNode()->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
        } else if (target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_NUMERIC) && IsETSIntEnumType()) {
            result = true;
            relation->GetNode()->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
        }
    } else if (target->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
        result = IsETSIntEnumType();
        if (result) {
            relation->GetNode()->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
        }
    } else if (target->IsETSBooleanType()) {
        result = true;
        relation->GetNode()->AddAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
    } else if (target->IsETSUnionType()) {
        auto &unionConstituentTypes = target->AsETSUnionType()->ConstituentTypes();
        for (auto *constituentType : unionConstituentTypes) {
            if (constituentType == GetDecl()->BoxedClass()->TsType()) {
                result = true;
                relation->GetNode()->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_ENUM);
                break;
            }
        }
    }
    relation->Result(result);
    return relation->IsTrue();
}

void ETSEnumType::AssignmentTarget(TypeRelation *const relation, Type *const source)
{
    auto checker = relation->GetChecker()->AsETSChecker();

    Type *const unboxedSource = checker->MaybeUnboxType(source);
    if (unboxedSource != source && !relation->OnlyCheckBoxingUnboxing()) {
        relation->GetNode()->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOX_TO_ENUM);
    }

    relation->Result(false);
    if (unboxedSource->IsETSEnumType()) {
        relation->Result(IsSameEnumType(unboxedSource->AsETSEnumType()));
    } else if (unboxedSource->IsETSStringType()) {
        relation->Result(IsSameEnumType(unboxedSource->AsETSStringEnumType()));
    }
}

void ETSEnumType::Cast(TypeRelation *relation, Type *target)
{
    if (target->IsETSEnumType()) {
        conversion::Identity(relation, this, target);
        return;
    }

    if (target->HasTypeFlag(TypeFlag::ETS_NUMERIC)) {
        relation->Result(true);
        return;
    }

    // NOTE(vpukhov): #20510 conversion rules
    if (target->IsETSObjectType()) {
        if (target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BOXED_ENUM)) {
            conversion::Boxing(relation, this);
            return;
        }

        if (target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_TYPE)) {
            auto unboxedTarget = relation->GetChecker()->AsETSChecker()->MaybeUnboxInRelation(target);
            if (unboxedTarget == nullptr) {
                conversion::Forbidden(relation);
                return;
            }
            Cast(relation, unboxedTarget);
            if (relation->IsTrue()) {
                conversion::Boxing(relation, unboxedTarget);
                return;
            }
            conversion::Forbidden(relation);
            return;
        }

        conversion::BoxingWideningReference(relation, this, target->AsETSObjectType());
        return;
    }
    conversion::Forbidden(relation);
}

Type *ETSEnumType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                               [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    return this;
}

void ETSEnumType::Identical(TypeRelation *const relation, Type *const other)
{
    relation->Result(other->IsETSEnumType() && IsSameEnumType(other->AsETSEnumType()));
}

void ETSEnumType::ToAssemblerType(std::stringstream &ss) const
{
    ToAssemblerTypeImpl<UType>(ss);
}

void ETSEnumType::ToDebugInfoType(std::stringstream &ss) const
{
    ToDebugInfoTypeImpl<UType>(ss);
}

void ETSEnumType::ToString(std::stringstream &ss, [[maybe_unused]] bool precise) const
{
    ss << decl_->Key()->Name();
}

const ir::TSEnumDeclaration *ETSEnumType::GetDecl() const noexcept
{
    return decl_;
}

Type *ETSEnumType::BoxedType() const noexcept
{
    return GetDecl()->BoxedClass()->TsType();
}

const ArenaVector<ir::AstNode *> &ETSEnumType::GetMembers() const noexcept
{
    return decl_->Members();
}

varbinder::LocalVariable *ETSEnumType::GetMemberVar() const noexcept
{
    ASSERT(IsLiteralType());
    return member_->Key()->AsIdentifier()->Variable()->AsLocalVariable();
}

util::StringView ETSEnumType::GetName() const noexcept
{
    return decl_->Key()->Name();
}

ETSEnumType::UType ETSEnumType::GetOrdinal() const noexcept
{
    ASSERT(IsLiteralType());
    return ordinal_;
}

ETSEnumType *ETSEnumType::LookupConstant(ETSChecker *const checker, const ir::Expression *const expression,
                                         const ir::Identifier *const prop) const
{
    if (!IsEnumTypeExpression(expression)) {
        if (expression->IsIdentifier() &&
            expression->AsIdentifier()->Variable()->HasFlag(varbinder::VariableFlags::TYPE_ALIAS)) {
            checker->LogTypeError({"Cannot refer to enum members through type alias."}, prop->Start());
        } else if (IsLiteralType()) {
            checker->LogTypeError({"Cannot refer to enum members through variable."}, prop->Start());
        } else {
            checker->LogTypeError({"Enum constant does not have property '", prop->Name(), "'."}, prop->Start());
        }
        return nullptr;
    }

    auto *const member = FindMember(prop->Name());
    if (member == nullptr) {
        checker->LogTypeError({"No enum constant named '", prop->Name(), "' in enum '", this, "'"}, prop->Start());
        return nullptr;
    }

    auto *const enumInterface = member->Key()->AsIdentifier()->Variable()->TsType()->AsETSEnumType();
    ASSERT(enumInterface->IsLiteralType());
    return enumInterface;
}

ETSFunctionType *ETSEnumType::LookupMethod(ETSChecker *checker, const ir::Expression *const expression,
                                           const ir::Identifier *const prop) const
{
    if (IsEnumTypeExpression(expression)) {
        return LookupTypeMethod(checker, prop);
    }

    ASSERT(IsEnumInstanceExpression(expression));
    return LookupConstantMethod(checker, prop);
}

bool ETSEnumType::IsSameEnumType(const ETSEnumType *const other) const noexcept
{
    return other->decl_ == decl_;
}

bool ETSEnumType::IsSameEnumLiteralType(const ETSEnumType *const other) const noexcept
{
    ASSERT(IsLiteralType() && IsSameEnumType(other));
    return member_ == other->member_;
}

bool ETSEnumType::IsEnumInstanceExpression(const ir::Expression *const expression) const noexcept
{
    ASSERT(IsSameEnumType(expression->TsType()->AsETSEnumType()));

    return IsEnumLiteralExpression(expression) || !IsEnumTypeExpression(expression);
}

bool ETSEnumType::IsEnumLiteralExpression(const ir::Expression *const expression) const noexcept
{
    ASSERT(IsSameEnumType(expression->TsType()->AsETSEnumType()));

    if (expression->IsMemberExpression()) {
        const auto *const memberExpr = expression->AsMemberExpression();
        return memberExpr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS &&
               IsEnumTypeExpression(memberExpr->Object());
    }

    return false;
}

bool ETSEnumType::IsEnumTypeExpression(const ir::Expression *const expression) const noexcept
{
    if (expression->TsType()->IsETSEnumType()) {
        ASSERT(IsSameEnumType(expression->TsType()->AsETSEnumType()));
    } else {
        return false;
    }

    if (expression->IsCallExpression()) {
        return false;
    }

    // clang-format off
    const auto *const localVar = [expression]() -> const varbinder::LocalVariable* {
        if (expression->IsMemberExpression()) {
            const auto *const memberExpr = expression->AsMemberExpression();
            return memberExpr->PropVar() != nullptr
                       ? memberExpr->PropVar()
                       : memberExpr->Object()->AsIdentifier()->Variable()->AsLocalVariable();
        }
        return expression->AsIdentifier()->Variable()->AsLocalVariable();
    }();
    // clang-format on
    ASSERT(localVar->Declaration() == decl_->Key()->AsIdentifier()->Variable()->Declaration() ||
           !localVar->HasFlag(varbinder::VariableFlags::ENUM_LITERAL));
    return localVar->HasFlag(varbinder::VariableFlags::ENUM_LITERAL);
}

ETSEnumType::Method ETSEnumType::FromIntMethod() const noexcept
{
    ASSERT(fromIntMethod_.globalSignature != nullptr && fromIntMethod_.memberProxyType == nullptr);
    return fromIntMethod_;
}

ETSEnumType::Method ETSEnumType::BoxedFromIntMethod() const noexcept
{
    ASSERT(boxedFromIntMethod_.globalSignature != nullptr && boxedFromIntMethod_.memberProxyType == nullptr);
    return boxedFromIntMethod_;
}

ETSEnumType::Method ETSEnumType::UnboxMethod() const noexcept
{
    ASSERT(unboxMethod_.globalSignature != nullptr && unboxMethod_.memberProxyType != nullptr);
    return unboxMethod_;
}

ETSEnumType::Method ETSEnumType::ValueOfMethod() const noexcept
{
    ASSERT(valueOfMethod_.globalSignature != nullptr && valueOfMethod_.memberProxyType != nullptr);
    return valueOfMethod_;
}

ETSEnumType::Method ETSEnumType::GetNameMethod() const noexcept
{
    ASSERT(getNameMethod_.globalSignature != nullptr && getNameMethod_.memberProxyType != nullptr);
    return getNameMethod_;
}

ETSEnumType::Method ETSEnumType::ToStringMethod() const noexcept
{
    ASSERT(toStringMethod_.globalSignature != nullptr && toStringMethod_.memberProxyType != nullptr);
    return toStringMethod_;
}

ETSEnumType::Method ETSEnumType::GetValueOfMethod() const noexcept
{
    ASSERT(getValueOfMethod_.globalSignature != nullptr && getValueOfMethod_.memberProxyType != nullptr);
    return getValueOfMethod_;
}

ETSEnumType::Method ETSEnumType::ValuesMethod() const noexcept
{
    ASSERT(valuesMethod_.globalSignature != nullptr && valuesMethod_.memberProxyType != nullptr);
    return valuesMethod_;
}

bool ETSEnumType::IsLiteralType() const noexcept
{
    return member_ != nullptr;
}

ir::TSEnumMember *ETSEnumType::FindMember(const util::StringView &name) const noexcept
{
    ASSERT(!IsLiteralType());
    const auto &members = GetMembers();
    auto memberIt = std::find_if(members.begin(), members.end(), [name](const ir::AstNode *const node) {
        return node->AsTSEnumMember()->Key()->AsIdentifier()->Name() == name;
    });
    if (memberIt != members.end()) {
        return (*memberIt)->AsTSEnumMember();
    }

    return nullptr;
}

ETSFunctionType *ETSEnumType::LookupConstantMethod(ETSChecker *const checker, const ir::Identifier *const prop) const
{
    if (prop->Name() == TO_STRING_METHOD_NAME) {
        ASSERT(toStringMethod_.memberProxyType != nullptr);
        return toStringMethod_.memberProxyType;
    }

    if (prop->Name() == VALUE_OF_METHOD_NAME) {
        ASSERT(valueOfMethod_.memberProxyType != nullptr);
        return valueOfMethod_.memberProxyType;
    }

    if (prop->Name() == GET_NAME_METHOD_NAME) {
        ASSERT(getNameMethod_.memberProxyType != nullptr);
        return getNameMethod_.memberProxyType;
    }

    checker->LogTypeError({"No enum item method called '", prop->Name(), "'"}, prop->Start());
    return nullptr;
}

ETSFunctionType *ETSEnumType::LookupTypeMethod(ETSChecker *const checker, const ir::Identifier *const prop) const
{
    if (prop->Name() == VALUES_METHOD_NAME) {
        ASSERT(valuesMethod_.memberProxyType != nullptr);
        return valuesMethod_.memberProxyType;
    }

    if (prop->Name() == GET_VALUE_OF_METHOD_NAME) {
        ASSERT(getValueOfMethod_.memberProxyType != nullptr);
        return getValueOfMethod_.memberProxyType;
    }

    checker->LogTypeError({"No enum type method called '", prop->Name(), "'"}, prop->Start());
    return nullptr;
}

}  // namespace ark::es2panda::checker
