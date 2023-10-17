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

#include "etsDynamicType.h"
#include "checker/ETSchecker.h"
#include "checker/types/ets/etsDynamicFunctionType.h"

namespace panda::es2panda::checker {

binder::LocalVariable *ETSDynamicType::GetPropertyDynamic(const util::StringView &name, const ETSChecker *checker) const
{
    auto it = properties_cache_.find(name);
    if (it != properties_cache_.end()) {
        return it->second;
    }

    binder::LocalVariable *var =
        binder::Scope::CreateVar<binder::PropertyDecl>(Allocator(), name, binder::VariableFlags::BUILTIN_TYPE, nullptr);
    var->SetTsType(checker->GlobalBuiltinDynamicType(lang_));
    properties_cache_.emplace(name, var);

    return var;
}

void ETSDynamicType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (has_decl_) {
        return ETSObjectType::AssignmentTarget(relation, source);
    }

    relation->Result(true);
}

bool ETSDynamicType::AssignmentSource(TypeRelation *relation, Type *target)
{
    if (has_decl_) {
        return ETSObjectType::AssignmentSource(relation, target);
    }

    if (target->HasTypeFlag(checker::TypeFlag::ETS_TYPE_TO_DYNAMIC)) {
        relation->Result(true);
    }
    return relation->IsTrue();
}

void ETSDynamicType::Cast(TypeRelation *relation, Type *target)
{
    if (has_decl_) {
        return ETSObjectType::Cast(relation, target);
    }

    if (relation->InCastingContext()) {
        relation->Result(true);
        return;
    }

    if (IsConvertableTo(target)) {
        relation->Result(true);
    }
}

bool ETSDynamicType::IsConvertableTo(Type *target) const
{
    return target->IsETSStringType() || target->IsLambdaObject() || target->IsETSDynamicType() ||
           target->HasTypeFlag(checker::TypeFlag::ETS_TYPE_TO_DYNAMIC | checker::TypeFlag::ETS_BOOLEAN);
}

ETSFunctionType *ETSDynamicType::CreateETSFunctionType(const util::StringView &name) const
{
    return Allocator()->New<ETSDynamicFunctionType>(name, Allocator(), lang_);
}

void ETSDynamicType::ToAssemblerType(std::stringstream &ss) const
{
    ss << compiler::Signatures::Dynamic::Type(lang_);
}

}  // namespace panda::es2panda::checker
