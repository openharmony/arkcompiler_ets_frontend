/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <algorithm>

#include "checker_test.h"

namespace test::utils {

checker_alias::Type *CheckerTest::FindClassType(varbinder_alias::ETSBinder *varbinder, std::string_view className)
{
    auto classDefs = varbinder->AsETSBinder()->GetRecordTable()->ClassDefinitions();
    auto baseClass = std::find_if(classDefs.begin(), classDefs.end(), [className](ir_alias::ClassDefinition *cdef) {
        return cdef->Ident()->Name().Is(className);
    });
    if (baseClass == classDefs.end()) {
        return nullptr;
    }
    return (*baseClass)->TsType();
}

checker_alias::Type *CheckerTest::FindTypeAlias(checker_alias::ETSChecker *checker, std::string_view aliasName)
{
    auto *foundVar =
        checker->Scope()->FindLocal(aliasName, varbinder_alias::ResolveBindingOptions::TYPE_ALIASES)->AsLocalVariable();
    if (foundVar == nullptr) {
        return nullptr;
    }
    return foundVar->Declaration()->Node()->AsTSTypeAliasDeclaration()->TypeAnnotation()->TsType();
}

}  // namespace test::utils