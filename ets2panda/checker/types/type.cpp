/**
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

#include "type.h"

#include "checker/types/typeFlag.h"
#include "checker/types/typeRelation.h"
#include "checker/types/ets/etsObjectType.h"

namespace ark::es2panda::checker {
bool Type::IsETSNullType() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::NULL_TYPE);
}

bool Type::IsETSUndefinedType() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::UNDEFINED_TYPE);
}

bool Type::IsETSNullLike() const
{
    // NOTE: vpukhov. should be true for 'null|undefined'
    return IsETSUndefinedType() || IsETSNullType();
}

bool Type::IsNullish() const
{
    return HasTypeFlag(TypeFlag::NULLISH);
}

bool Type::IsNullishOrNullLike() const
{
    return IsNullish() || IsETSNullLike();
}

bool Type::ContainsNull() const
{
    return HasTypeFlag(TypeFlag::NULL_TYPE);
}

bool Type::ContainsUndefined() const
{
    return HasTypeFlag(TypeFlag::UNDEFINED);
}

bool Type::IsETSStringType() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::STRING);
}

bool Type::IsETSBigIntType() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::BUILTIN_BIGINT);
}

bool Type::IsETSAsyncFuncReturnType() const
{
    return IsETSObjectType() && AsETSObjectType()->HasObjectFlag(ETSObjectFlags::ASYNC_FUNC_RETURN_TYPE);
}

bool Type::IsLambdaObject() const
{
    if (IsETSObjectType() && (AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::FUNCTIONAL_INTERFACE) ||
                              AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::CLASS))) {
        auto *invoke = AsETSObjectType()->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke");
        if (invoke != nullptr && invoke->TsType() != nullptr && invoke->TsType()->IsETSFunctionType()) {
            return true;
        }
    }
    return false;
}

void Type::ToStringAsSrc(std::stringstream &ss) const
{
    ToString(ss);
}

void Type::Identical(TypeRelation *relation, Type *other)
{
    relation->Result(typeFlags_ == other->TypeFlags());
}

bool Type::AssignmentSource([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *target)
{
    return false;
}

TypeFacts Type::GetTypeFacts() const
{
    return TypeFacts::NONE;
}

void Type::Compare([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *other) {}

void Type::Cast(TypeRelation *const relation, [[maybe_unused]] Type *target)
{
    relation->Result(false);
}

void Type::CastTarget(TypeRelation *const relation, [[maybe_unused]] Type *source)
{
    relation->Result(false);
}

void Type::IsSupertypeOf(TypeRelation *const relation, [[maybe_unused]] Type *source)
{
    relation->Result(false);
}

void Type::IsSubtypeOf(TypeRelation *const relation, [[maybe_unused]] Type *target)
{
    relation->Result(false);
}

Type *Type::AsSuper([[maybe_unused]] Checker *checker, [[maybe_unused]] varbinder::Variable *sourceVar)
{
    return nullptr;
}

Type *Type::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                        [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    return nullptr;
}

Type *Type::Substitute([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] const Substitution *substitution)
{
    return this;
}
}  // namespace ark::es2panda::checker
