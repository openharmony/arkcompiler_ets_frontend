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

#include "etsExtensionFuncHelperType.h"

#include "etsFunctionType.h"

namespace panda::es2panda::checker {
/*
    !NB etsExtensionFuncHelperType is to support extension function when we try to resolve a member expression
    like "a.b", there are different cases:
        1. there is a method or prop whose name is "b" in class A
        2. there is an instance extension of class A, function A.b() {}
        3. both 1 and 2 existed
    in order to figure out a representation for case 3, we need the etsExtensionFuncHelperType
*/

void ETSExtensionFuncHelperType::ToString(std::stringstream &ss) const
{
    class_method_type_->ToString(ss);
    ss << " | ";
    extension_function_type_->ToString(ss);
}

void ETSExtensionFuncHelperType::AssignmentTarget(TypeRelation *relation, Type *source)
{
    if (!source->IsETSFunctionType()) {
        return;
    }

    if (relation->IsAssignableTo(source->AsETSFunctionType(), class_method_type_)) {
        return;
    }

    if (relation->IsAssignableTo(source->AsETSFunctionType(), extension_function_type_)) {
        return;
    }
}
}  // namespace panda::es2panda::checker
