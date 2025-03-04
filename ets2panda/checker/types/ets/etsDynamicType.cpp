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

#include "etsDynamicType.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/types/ets/etsDynamicFunctionType.h"

namespace ark::es2panda::checker {

varbinder::LocalVariable *ETSDynamicType::GetPropertyDynamic(const util::StringView &name,
                                                             const ETSChecker *checker) const
{
    auto it = propertiesCache_.find(name);
    if (it != propertiesCache_.end()) {
        return it->second;
    }

    varbinder::LocalVariable *var = varbinder::Scope::CreateVar<varbinder::PropertyDecl>(
        Allocator(), name, varbinder::VariableFlags::BUILTIN_TYPE, nullptr);
    var->SetTsType(checker->GlobalBuiltinDynamicType(lang_));
    propertiesCache_.emplace(name, var);

    return var;
}

void ETSDynamicType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (hasDecl_) {
        return ETSObjectType::AssignmentTarget(relation, source);
    }

    if (relation->ApplyBoxing() && !relation->IsTrue() && IsConvertible(source)) {
        relation->Result(true);
        return;
    }

    if (source->IsETSDynamicType()) {
        relation->Result(true);
    }
}

bool ETSDynamicType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (hasDecl_) {
        return ETSObjectType::AssignmentSource(relation, target);
    }

    if (relation->ApplyUnboxing() && IsConvertible(target)) {
        relation->Result(true);
        return true;
    }

    if (target->IsETSDynamicType()) {
        relation->Result(true);
    }
    return relation->IsTrue();
}

void ETSDynamicType::Cast(TypeRelation *relation, Type *target)
{
    if (hasDecl_) {
        return ETSObjectType::Cast(relation, target);
    }

    if (relation->InCastingContext() || IsConvertible(target)) {
        relation->Result(true);
        return;
    }

    conversion::Forbidden(relation);
}

void ETSDynamicType::CastTarget(TypeRelation *relation, Type *source)
{
    if (hasDecl_) {
        ETSObjectType::CastTarget(relation, source);
        return;
    }

    if (relation->InCastingContext() || IsConvertible(source)) {
        relation->Result(true);
        return;
    }

    conversion::Forbidden(relation);
}

bool ETSDynamicType::IsConvertible(Type const *target)
{
    return target->IsETSDynamicType() || target->IsETSObjectType() || target->IsETSArrayType() ||
           target->IsETSTupleType() || target->IsETSFunctionType() ||
           target->HasTypeFlag(checker::TypeFlag::ETS_CONVERTIBLE_TO_NUMERIC | checker::TypeFlag::ETS_BOOLEAN);
}

ETSFunctionType *ETSDynamicType::CreateMethodTypeForProp(const util::StringView &name) const
{
    auto checker = GetRelation()->GetChecker()->AsETSChecker();
    return checker->CreateETSDynamicMethodType(name, {{}, Allocator()->Adapter()}, lang_);
}

void ETSDynamicType::ToAssemblerType(std::stringstream &ss) const
{
    ss << compiler::Signatures::Dynamic::Type(lang_);
}

}  // namespace ark::es2panda::checker
