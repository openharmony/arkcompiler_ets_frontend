/*
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

#ifndef ES2PANDA_EVALUATE_ENTITY_DECLARATOR_INL_H
#define ES2PANDA_EVALUATE_ENTITY_DECLARATOR_INL_H

#include "evaluate/scopedDebugInfoPlugin.h"
#include "evaluate/entityDeclarator.h"
#include "evaluate/irCheckHelper.h"

#include <utility>

namespace ark::es2panda::evaluate {

template <typename F>
varbinder::Variable *EntityDeclarator::ImportGlobalEntity(util::StringView pathToDeclSource, util::StringView declName,
                                                          parser::Program *importerProgram,
                                                          util::StringView importedName, F &&irCreator)
{
    ASSERT(importerProgram);
    parser::Program *program = debugInfoPlugin_.GetProxyProgramsCache()->GetProgram(pathToDeclSource);

    helpers::SafeStateScope s(debugInfoPlugin_.GetIrCheckHelper()->GetChecker(), debugInfoPlugin_.GetETSBinder());

    auto &entitiesMap = GetOrCreateEntitiesMap(program);
    auto *var = FindEntityVariable(entitiesMap, declName);

    if (var == nullptr) {
        var = std::invoke(std::forward<F>(irCreator), debugInfoPlugin_.GetDebugInfoDeserializer(), program,
                          pathToDeclSource, declName);
        if (var != nullptr) {
            if (!entitiesMap.emplace(declName, var).second) {
                LOG(FATAL, ES2PANDA) << "Failed to emplace " << importedName << " in entity map.";
            }
        }
    }

    if (var != nullptr && program != importerProgram) {
        CreateAndInsertImportStatement(pathToDeclSource, declName, importerProgram, importedName, var);
    }
    return var;
}

}  // namespace ark::es2panda::evaluate

#endif  // ES2PANDA_EVALUATE_ENTITY_DECLARATOR_INL_H
