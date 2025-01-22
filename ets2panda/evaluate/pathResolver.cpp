/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "evaluate/pathResolver.h"
#include "evaluate/debugInfoStorage.h"

#include "parser/program/program.h"

namespace ark::es2panda::evaluate {

void PathResolver::FindImportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                                         std::string_view entityName)
{
    // NOTE: cache all the resolved paths.
    auto *table = debugInfoStorage_.GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return;
    }

    // `import * as B from "C"` should not be searched, as it handled differently in compiler.
    const auto &imports = table->GetImports();
    auto optOverloadSet = imports.find(entityName);
    if (optOverloadSet == imports.end()) {
        return;
    }

    ES2PANDA_ASSERT(!optOverloadSet->second.empty());
    for (const auto &[path, entity] : optOverloadSet->second) {
        // `import {A as B} from "C"`
        FindExportedFunctions(overloadSet, path, entity);
    }
}

void PathResolver::FindExportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                                         std::string_view entityName)
{
    // NOTE: cache all the resolved paths.
    auto *table = debugInfoStorage_.GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return;
    }

    const auto &exports = table->GetExports();
    const auto optOverloadSet = exports.find(entityName);
    if (optOverloadSet != exports.end()) {
        ES2PANDA_ASSERT(!optOverloadSet->second.empty());
        for (const auto &[path, entity] : optOverloadSet->second) {
            // `export {A as B} from "C"`
            if (path.empty()) {
                overloadSet.push_back(EntityInfo(filePath, entity));
            } else {
                FindExportedFunctions(overloadSet, path, entity);
            }
        }
    }

    // Still need to traverse re-export-all statements to fill the complete overload set.
    const auto optReExportAll = exports.find(STAR_IMPORT);
    if (optReExportAll != exports.end()) {
        ES2PANDA_ASSERT(!optReExportAll->second.empty());
        for (const auto &[path, entity] : optReExportAll->second) {
            // export * from "C"
            (void)entity;
            ES2PANDA_ASSERT(entity == STAR_IMPORT);

            FindExportedFunctions(overloadSet, path, entityName);
        }
    }
}

std::string_view PathResolver::FindNamedImportAll(std::string_view filePath, std::string_view bindingName)
{
    auto *table = debugInfoStorage_.GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return {};
    }

    const auto &imports = table->GetImports();
    auto optEntity = imports.find(bindingName);
    if (optEntity == imports.end()) {
        return {};
    }

    ES2PANDA_ASSERT(!optEntity->second.empty());
    for (const auto &[path, entity] : optEntity->second) {
        if (entity == STAR_IMPORT) {
            return path;
        }
    }
    return {};
}

std::optional<EntityInfo> PathResolver::FindImportedEntity(std::string_view filePath, std::string_view entityName)
{
    // NOTE: cache all the resolved paths.
    auto *table = debugInfoStorage_.GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return {};
    }

    // `import * as B from "C"` should not be searched, as it handled differently in compiler.
    const auto &imports = table->GetImports();
    auto optEntity = imports.find(entityName);
    if (optEntity == imports.end()) {
        return {};
    }

    ES2PANDA_ASSERT(!optEntity->second.empty());
    if (optEntity->second.size() > 1) {
        // Have more than one imports for the given name - it could not be a variable.
        return {};
    }
    // `import {A as B} from "C"`
    auto [path, entity] = optEntity->second[0];
    return FindExportedEntity(path, entity);
}

// Note that the current implementation does not guarantee that the found entity is indeed a variable,
// so users must check it manually by traversing the found file's ETSGLOBAL fields.
std::optional<EntityInfo> PathResolver::FindExportedEntity(std::string_view filePath, std::string_view entityName)
{
    // NOTE: cache all the resolved paths.
    auto *table = debugInfoStorage_.GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return {};
    }

    const auto &exports = table->GetExports();
    const auto optOverloadSet = exports.find(entityName);
    if (optOverloadSet != exports.end()) {
        ES2PANDA_ASSERT(!optOverloadSet->second.empty());
        if (optOverloadSet->second.size() > 1) {
            // Have more than one imports for the given name, but we search for the single one - variable or class.
            return {};
        }
        // export {A as B} from "C"
        const auto &[path, entity] = optOverloadSet->second[0];
        if (path.empty()) {
            return EntityInfo(filePath, entity);
        }
        return FindExportedEntity(path, entity);
    }

    const auto optReExportAll = exports.find(STAR_IMPORT);
    if (optReExportAll != exports.end()) {
        ES2PANDA_ASSERT(!optReExportAll->second.empty());
        for (const auto &[path, entity] : optReExportAll->second) {
            // export * from "C"
            (void)entity;
            ES2PANDA_ASSERT(entity == STAR_IMPORT);

            auto optResult = FindExportedEntity(path, entityName);
            if (optResult) {
                return optResult;
            }
        }
    }

    return {};
}

}  //  namespace ark::es2panda::evaluate
