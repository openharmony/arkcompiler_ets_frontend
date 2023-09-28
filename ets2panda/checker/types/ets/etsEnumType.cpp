/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/conversion.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumMember.h"

namespace panda::es2panda::checker {
ETSEnumType::ETSEnumType(const ir::TSEnumDeclaration *const enum_decl, UType ordinal,
                         const ir::TSEnumMember *const member)
    : Type(TypeFlag::ETS_ENUM), decl_(enum_decl), ordinal_ {ordinal}, member_(member)
{
}

bool ETSEnumType::AssignmentSource(TypeRelation *const relation, Type *const target)
{
    relation->Result(target->IsETSEnumType() && IsSameEnumType(target->AsETSEnumType()));
    return relation->IsTrue();
}

void ETSEnumType::AssignmentTarget(TypeRelation *const relation, Type *const source)
{
    relation->Result(source->IsETSEnumType() && IsSameEnumType(source->AsETSEnumType()));
}

void ETSEnumType::Cast(TypeRelation *relation, Type *target)
{
    if (target->IsIntType()) {
        relation->Result(true);
        return;
    }

    conversion::Forbidden(relation);
}

Type *ETSEnumType::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                               [[maybe_unused]] GlobalTypesHolder *global_types)
{
    return this;
}

void ETSEnumType::Identical(TypeRelation *const relation, Type *const other)
{
    if (other->IsETSEnumType()) {
        auto *const other_enum_type = other->AsETSEnumType();
        relation->Result(IsSameEnumType(other_enum_type) && member_ == other_enum_type->member_);
        return;
    }

    relation->Result(false);
}

void ETSEnumType::ToAssemblerType(std::stringstream &ss) const
{
    ToAssemblerTypeImpl<UType>(ss);
}

void ETSEnumType::ToDebugInfoType(std::stringstream &ss) const
{
    ToDebugInfoTypeImpl<UType>(ss);
}

void ETSEnumType::ToString(std::stringstream &ss) const
{
    ss << decl_->Key()->Name();
}

const ir::TSEnumDeclaration *ETSEnumType::GetDecl() const noexcept
{
    return decl_;
}

const ArenaVector<ir::AstNode *> &ETSEnumType::GetMembers() const noexcept
{
    return decl_->Members();
}

binder::LocalVariable *ETSEnumType::GetMemberVar() const noexcept
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
        checker->ThrowTypeError({"Enum constant do not have property '", prop->Name(), "'"}, prop->Start());
    }

    auto *const member = FindMember(prop->Name());
    if (member == nullptr) {
        checker->ThrowTypeError({"No enum constant named '", prop->Name(), "' in enum '", this, "'"}, prop->Start());
    }

    auto *const enum_constant_type = member->Key()->AsIdentifier()->Variable()->TsType()->AsETSEnumType();
    ASSERT(enum_constant_type->IsLiteralType());
    return enum_constant_type;
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
        const auto *const member_expr = expression->AsMemberExpression();
        return member_expr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS &&
               IsEnumTypeExpression(member_expr->Object());
    }

    return false;
}

bool ETSEnumType::IsEnumTypeExpression(const ir::Expression *const expression) const noexcept
{
    ASSERT(IsSameEnumType(expression->TsType()->AsETSEnumType()));

    if (expression->IsCallExpression()) {
        return false;
    }

    const auto *const local_var = [expression]() -> const binder::LocalVariable * {
        if (expression->IsMemberExpression()) {
            const auto *const member_expr = expression->AsMemberExpression();
            return member_expr->PropVar() != nullptr
                       ? member_expr->PropVar()
                       : member_expr->Object()->AsIdentifier()->Variable()->AsLocalVariable();
        }
        return expression->AsIdentifier()->Variable()->AsLocalVariable();
    }();

    ASSERT(local_var->Declaration() == decl_->Key()->AsIdentifier()->Variable()->Declaration() ||
           !local_var->HasFlag(binder::VariableFlags::ENUM_LITERAL));

    return local_var->HasFlag(binder::VariableFlags::ENUM_LITERAL);
}

ETSEnumType::Method ETSEnumType::FromIntMethod() const noexcept
{
    ASSERT(from_int_method_.global_signature != nullptr && from_int_method_.member_proxy_type == nullptr);
    return from_int_method_;
}

ETSEnumType::Method ETSEnumType::GetValueMethod() const noexcept
{
    ASSERT(get_value_method_.global_signature != nullptr && get_value_method_.member_proxy_type != nullptr);
    return get_value_method_;
}

ETSEnumType::Method ETSEnumType::GetNameMethod() const noexcept
{
    ASSERT(get_name_method_.global_signature != nullptr && get_name_method_.member_proxy_type != nullptr);
    return get_name_method_;
}

ETSEnumType::Method ETSEnumType::ToStringMethod() const noexcept
{
    ASSERT(to_string_method_.global_signature != nullptr && to_string_method_.member_proxy_type != nullptr);
    return to_string_method_;
}

ETSEnumType::Method ETSEnumType::ValueOfMethod() const noexcept
{
    ASSERT(value_of_method_.global_signature != nullptr && value_of_method_.member_proxy_type != nullptr);
    return value_of_method_;
}

ETSEnumType::Method ETSEnumType::ValuesMethod() const noexcept
{
    ASSERT(values_method_.global_signature != nullptr && values_method_.member_proxy_type != nullptr);
    return values_method_;
}

bool ETSEnumType::IsLiteralType() const noexcept
{
    return member_ != nullptr;
}

ir::TSEnumMember *ETSEnumType::FindMember(const util::StringView &name) const noexcept
{
    ASSERT(!IsLiteralType());
    const auto &members = GetMembers();
    auto member_it = std::find_if(members.begin(), members.end(), [name](const ir::AstNode *const node) {
        return node->AsTSEnumMember()->Key()->AsIdentifier()->Name() == name;
    });

    if (member_it != members.end()) {
        return (*member_it)->AsTSEnumMember();
    }

    return nullptr;
}

ETSFunctionType *ETSEnumType::LookupConstantMethod(ETSChecker *const checker, const ir::Identifier *const prop) const
{
    if (prop->Name() == TO_STRING_METHOD_NAME) {
        ASSERT(to_string_method_.member_proxy_type != nullptr);
        return to_string_method_.member_proxy_type;
    }

    if (prop->Name() == GET_VALUE_METHOD_NAME) {
        ASSERT(get_value_method_.member_proxy_type != nullptr);
        return get_value_method_.member_proxy_type;
    }

    if (prop->Name() == GET_NAME_METHOD_NAME) {
        ASSERT(get_name_method_.member_proxy_type != nullptr);
        return get_name_method_.member_proxy_type;
    }

    checker->ThrowTypeError({"No enum item method called '", prop->Name(), "'"}, prop->Start());
}

ETSFunctionType *ETSEnumType::LookupTypeMethod(ETSChecker *const checker, const ir::Identifier *const prop) const
{
    if (prop->Name() == VALUES_METHOD_NAME) {
        ASSERT(values_method_.member_proxy_type != nullptr);
        return values_method_.member_proxy_type;
    }

    if (prop->Name() == VALUE_OF_METHOD_NAME) {
        ASSERT(value_of_method_.member_proxy_type != nullptr);
        return value_of_method_.member_proxy_type;
    }

    checker->ThrowTypeError({"No enum type method called '", prop->Name(), "'"}, prop->Start());
}

}  // namespace panda::es2panda::checker
