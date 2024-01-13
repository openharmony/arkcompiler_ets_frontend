/*
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

#include "etsTypeParameter.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameter.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"

namespace panda::es2panda::checker {
void ETSTypeParameter::ToString(std::stringstream &ss) const
{
    ss << declNode_->Name()->Name();

    if (IsNullish()) {
        if (ContainsNull()) {
            ss << "|null";
        }
        if (ContainsUndefined()) {
            ss << "|undefined";
        }
    }
}

void ETSTypeParameter::Identical([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *other)
{
    if ((ContainsNull() != other->ContainsNull()) || (ContainsUndefined() != other->ContainsUndefined())) {
        return;
    }

    if (other->IsETSTypeParameter() && other->AsETSTypeParameter()->GetOriginal() == GetOriginal()) {
        relation->Result(true);
    }
}

bool ETSTypeParameter::AssignmentSource([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *target)
{
    return relation->Result(false);
}

void ETSTypeParameter::AssignmentTarget([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *source)
{
    if (source->IsETSNullType()) {
        relation->Result(ContainsNull());
        return;
    }
    if (source->IsETSUndefinedType()) {
        relation->Result(ContainsUndefined());
        return;
    }

    if ((source->ContainsNull() && !ContainsNull()) || (source->ContainsUndefined() && !ContainsUndefined())) {
        relation->Result(false);
        return;
    }
    if (source->IsETSTypeParameter() && source->AsETSTypeParameter()->GetOriginal() == GetOriginal()) {
        relation->Result(true);
        return;
    }

    IsSupertypeOf(relation, source);
}

void ETSTypeParameter::Cast(TypeRelation *relation, Type *target)
{
    if (target->IsSupertypeOf(relation, this), relation->IsTrue()) {
        relation->RemoveFlags(TypeRelationFlag::UNCHECKED_CAST);
        relation->Result(true);
        return;
    }

    // NOTE(vpukhov): adjust UNCHECKED_CAST flags
    if (target->IsETSObjectType()) {
        relation->RemoveFlags(TypeRelationFlag::UNCHECKED_CAST);
    }
    relation->Result(relation->InCastingContext());
}

void ETSTypeParameter::CastTarget(TypeRelation *relation, Type *source)
{
    if (IsSupertypeOf(relation, source), relation->IsTrue()) {
        relation->RemoveFlags(TypeRelationFlag::UNCHECKED_CAST);
        relation->Result(true);
        return;
    }

    relation->Result(relation->InCastingContext());
}

void ETSTypeParameter::IsSupertypeOf([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *source)
{
    if (Identical(relation, source), relation->IsTrue()) {
        return;
    }

    if (source->IsETSTypeParameter()) {
        source->AsETSTypeParameter()->ConstraintIsSubtypeOf(relation, this);
        return;
    }

    relation->Result(false);
}

Type *ETSTypeParameter::Instantiate([[maybe_unused]] ArenaAllocator *allocator, [[maybe_unused]] TypeRelation *relation,
                                    [[maybe_unused]] GlobalTypesHolder *globalTypes)
{
    auto *const checker = relation->GetChecker()->AsETSChecker();

    auto *const copiedType = checker->CreateTypeParameter();
    copiedType->AddTypeFlag(TypeFlag::GENERIC);
    copiedType->SetDeclNode(GetDeclNode());
    copiedType->SetDefaultType(GetDefaultType());
    copiedType->SetConstraintType(GetConstraintType());
    copiedType->SetVariable(Variable());
    return copiedType;
}

Type *ETSTypeParameter::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }
    auto *const checker = relation->GetChecker()->AsETSChecker();
    auto *original = GetOriginal();
    if (auto repl = substitution->find(original); repl != substitution->end()) {
        auto *replType = repl->second;
        /* Any other flags we need to copy? */

        /* The check this != base is a kludge to distinguish bare type parameter T
           with a nullish constraint (like the default Object?) from explicitly nullish T?
        */
        if (this != original && ((ContainsNull() && !replType->ContainsNull()) ||
                                 (ContainsUndefined() && !replType->ContainsUndefined()))) {
            // this type is explicitly marked as nullish
            ASSERT(replType->IsETSObjectType() || replType->IsETSArrayType() || replType->IsETSFunctionType() ||
                   replType->IsETSTypeParameter());
            auto nullishFlags = TypeFlag(TypeFlags() & TypeFlag::NULLISH);
            auto *newReplType = checker->CreateNullishType(replType, nullishFlags, checker->Allocator(), relation,
                                                           checker->GetGlobalTypesHolder());
            replType = newReplType;
        }
        return replType;
    }

    return this;
}

Type *ETSTypeParameter::EffectiveConstraint(ETSChecker const *checker) const
{
    return HasConstraint() ? GetConstraintType() : checker->GlobalETSNullishObjectType();
}

void ETSTypeParameter::ToAssemblerType(std::stringstream &ss) const
{
    if (HasConstraint()) {
        GetConstraintType()->ToAssemblerType(ss);
    } else {
        ss << compiler::Signatures::BUILTIN_OBJECT;
    }
}

void ETSTypeParameter::ToDebugInfoType(std::stringstream &ss) const
{
    if (HasConstraint()) {
        GetConstraintType()->ToDebugInfoType(ss);
    } else {
        ETSObjectType::DebugInfoTypeFromName(ss, compiler::Signatures::BUILTIN_OBJECT);
    }
}

ETSTypeParameter *ETSTypeParameter::GetOriginal() const
{
    return GetDeclNode()->Name()->Variable()->TsType()->AsETSTypeParameter();
}

}  // namespace panda::es2panda::checker
