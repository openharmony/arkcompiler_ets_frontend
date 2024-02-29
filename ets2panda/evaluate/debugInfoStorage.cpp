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

#include "evaluate/debugInfoStorage.h"
#include "assembler/assembly-type.h"
#include "generated/signatures.h"

namespace ark::es2panda::evaluate {

static std::string GetFullRecordName(const panda_file::File &pf, const panda_file::File::EntityId &classId)
{
    std::string name = utf::Mutf8AsCString(pf.GetStringData(classId).data);

    auto type = pandasm::Type::FromDescriptor(name);
    type = pandasm::Type(type.GetComponentName(), type.GetRank());

    return type.GetPandasmName();
}

static bool EndsWith(std::string_view str, std::string_view suffix)
{
    auto pos = str.rfind(suffix);
    return pos != std::string::npos && (str.size() - pos) == suffix.size();
}

ImportExportTable::ImportExportTable(ArenaAllocator *allocator)
    : imports_(allocator->Adapter()), exports_(allocator->Adapter())
{
}

DebugInfoStorage::DebugInfoStorage(const CompilerOptions &options, ArenaAllocator *allocator)
    : allocator_(allocator), sourceFileToDebugInfo_(allocator->Adapter()), moduleNameToDebugInfo_(allocator->Adapter())
{
    for (const auto &pfPath : options.evalContextPandaFiles) {
        LoadFileDebugInfo(pfPath);
    }
}

void DebugInfoStorage::LoadFileDebugInfo(std::string_view pfPath)
{
    auto pf = panda_file::OpenPandaFile(pfPath);
    if (!pf) {
        LOG(FATAL, ES2PANDA) << "Failed to load a provided abc file: " << pfPath;
    }

    for (auto id : pf->GetClasses()) {
        panda_file::File::EntityId classId(id);
        if (pf->IsExternal(classId)) {
            continue;
        }

        auto recordName = GetFullRecordName(*pf, classId);
        if (!EndsWith(recordName, compiler::Signatures::ETS_GLOBAL)) {
            continue;
        }

        std::string moduleName = "";
        auto pos = recordName.find_last_of('.');
        if (pos != std::string::npos) {
            moduleName = recordName.substr(0, pos);
        }

        panda_file::ClassDataAccessor cda(*pf, classId);
        auto sourceFileId = cda.GetSourceFileId();
        ASSERT(sourceFileId.has_value());
        std::string_view sourceFileName = utf::Mutf8AsCString(pf->GetStringData(*sourceFileId).data);

        auto *debugInfo = allocator_->New<FileDebugInfo>(std::move(pf), std::move(cda), std::move(moduleName));
        sourceFileToDebugInfo_.emplace(sourceFileName, debugInfo);
        moduleNameToDebugInfo_.emplace(std::string_view(debugInfo->moduleName), debugInfo);
        return;
    }

    LOG(FATAL, ES2PANDA) << "ETSGLOBAL not found in provided file: " << pfPath;
}

const panda_file::File *DebugInfoStorage::GetPandaFile(std::string_view filePath)
{
    auto iter = sourceFileToDebugInfo_.find(filePath);
    if (iter == sourceFileToDebugInfo_.end()) {
        return nullptr;
    }
    return iter->second->pf.get();
}

const ImportExportTable *DebugInfoStorage::GetImportExportTable(std::string_view filePath)
{
    auto iter = sourceFileToDebugInfo_.find(filePath);
    if (iter == sourceFileToDebugInfo_.end()) {
        return nullptr;
    }
    return &LazyLoadImportExportTable(iter->second);
}

panda_file::ClassDataAccessor *DebugInfoStorage::GetGlobalClassAccessor(std::string_view filePath)
{
    auto iter = sourceFileToDebugInfo_.find(filePath);
    if (iter == sourceFileToDebugInfo_.end()) {
        return nullptr;
    }
    return &iter->second->globalClassAcc;
}

std::string_view DebugInfoStorage::GetModuleName(std::string_view filePath)
{
    auto iter = sourceFileToDebugInfo_.find(filePath);
    if (iter == sourceFileToDebugInfo_.end()) {
        return "";
    }
    return iter->second->moduleName;
}

std::string_view DebugInfoStorage::FindNamedImportAll(std::string_view filePath, std::string_view bindingName)
{
    auto *table = GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return {};
    }

    const auto &imports = table->GetImports();
    auto optEntity = imports.find(bindingName);
    if (optEntity == imports.end()) {
        return "";
    }

    ASSERT(!optEntity->second.empty());
    for (const auto &[path, entity] : optEntity->second) {
        if (entity == STAR_IMPORT) {
            return path;
        }
    }
    return "";
}

panda_file::File::EntityId DebugInfoStorage::FindClass(std::string_view filePath, std::string_view className)
{
    auto iter = sourceFileToDebugInfo_.find(filePath);
    if (iter == sourceFileToDebugInfo_.end()) {
        return panda_file::File::EntityId();
    }

    const auto &records = LazyLoadRecords(iter->second);

    auto classIter = records.find(className);
    return classIter == records.end() ? panda_file::File::EntityId() : classIter->second;
}

std::optional<EntityInfo> DebugInfoStorage::FindImportedEntity(std::string_view filePath, std::string_view entityName)
{
    // TODO: cache all the resolved paths.
    auto *table = GetImportExportTable(filePath);
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

    ASSERT(!optEntity->second.empty());
    if (optEntity->second.size() > 1) {
        // Have more than one imports for the given name - it could not be a variable.
        return {};
    }
    // `import {A as B} from "C"`
    auto [path, entity] = optEntity->second[0];
    return FindExportedEntity(path, entity);
}

void DebugInfoStorage::FindImportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                                             std::string_view entityName)
{
    // TODO: cache all the resolved paths.
    auto *table = GetImportExportTable(filePath);
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

    ASSERT(!optOverloadSet->second.empty());
    for (const auto &[path, entity] : optOverloadSet->second) {
        // `import {A as B} from "C"`
        FindExportedFunctions(overloadSet, path, entity);
    }
}

// Note that the current implementation does not guarantee that the found entity is indeed a variable,
// so users must check it manually by traversing the found file's ETSGLOBAL fields.
std::optional<EntityInfo> DebugInfoStorage::FindExportedEntity(std::string_view filePath, std::string_view entityName)
{
    // TODO: cache all the resolved paths.
    auto *table = GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return {};
    }

    const auto &exports = table->GetExports();
    const auto optOverloadSet = exports.find(entityName);
    if (optOverloadSet != exports.end()) {
        ASSERT(!optOverloadSet->second.empty());
        if (optOverloadSet->second.size() > 1) {
            // Have more than one imports for the given name, but we search for the single one - variable or class.
            return {};
        }
        // export {A as B} from "C"
        const auto &[path, entity] = optOverloadSet->second[0];
        if (path == "") {
            return EntityInfo(filePath, entity);
        }
        return FindExportedEntity(path, entity);
    }

    const auto optReExportAll = exports.find(STAR_IMPORT);
    if (optReExportAll != exports.end()) {
        ASSERT(!optReExportAll->second.empty());
        for (const auto &[path, entity] : optReExportAll->second) {
            // export * from "C"
            (void)entity;
            ASSERT(entity == STAR_IMPORT);

            auto optResult = FindExportedEntity(path, entityName);
            if (optResult) {
                return optResult;
            }
        }
    }

    return {};
}

void DebugInfoStorage::FindExportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                                             std::string_view entityName)
{
    // TODO: cache all the resolved paths.
    auto *table = GetImportExportTable(filePath);
    if (table == nullptr) {
        LOG(WARNING, ES2PANDA) << "Failed to find import/export table for " << filePath;
        return;
    }

    const auto &exports = table->GetExports();
    const auto optOverloadSet = exports.find(entityName);
    if (optOverloadSet != exports.end()) {
        ASSERT(!optOverloadSet->second.empty());
        for (const auto &[path, entity] : optOverloadSet->second) {
            // `export {A as B} from "C"`
            if (path == "") {
                overloadSet.push_back(EntityInfo(filePath, entity));
            } else {
                FindExportedFunctions(overloadSet, path, entity);
            }
        }
    }

    // Still need to traverse re-export-all statements to fill the complete overload set.
    const auto optReExportAll = exports.find(STAR_IMPORT);
    if (optReExportAll != exports.end()) {
        ASSERT(!optReExportAll->second.empty());
        for (const auto &[path, entity] : optReExportAll->second) {
            // export * from "C"
            (void)entity;
            ASSERT(entity == STAR_IMPORT);

            FindExportedFunctions(overloadSet, path, entityName);
        }
    }
}

bool DebugInfoStorage::FillEvaluateContext(EvaluateContext &context)
{
    const auto *contextPandaFile = GetPandaFile(context.sourceFilePath.Utf8());
    if (contextPandaFile == nullptr) {
        LOG(WARNING, ES2PANDA) << "Could not find context file: " << context.sourceFilePath << std::endl;
        return false;
    }

    context.file = contextPandaFile;
    context.extractor = std::make_unique<panda_file::DebugInfoExtractor>(contextPandaFile);

    for (auto methodId : context.extractor->GetMethodIdList()) {
        for (const auto &entry : context.extractor->GetLineNumberTable(methodId)) {
            if (context.lineNumber == entry.line) {
                context.methodId = methodId;
                context.bytecodeOffset = entry.offset;
                util::UString sourceFilePath(std::string_view(context.extractor->GetSourceFile(methodId)), allocator_);
                context.sourceFilePath = sourceFilePath.View();
                return true;
            }
        }
    }
    LOG(WARNING, ES2PANDA) << "Could not find code at line: " << context.lineNumber << std::endl;
    return false;
}

const ImportExportTable &DebugInfoStorage::LazyLoadImportExportTable(FileDebugInfo *info)
{
    if (info->importExportTable.has_value()) {
        return *info->importExportTable;
    }

    // TODO: load table after it is implemented in compiler.
    info->importExportTable.emplace(allocator_);
    return info->importExportTable.value();
}

const DebugInfoStorage::FileDebugInfo::RecordsMap &DebugInfoStorage::LazyLoadRecords(FileDebugInfo *info)
{
    if (info->records.has_value()) {
        return *info->records;
    }

    info->records.emplace(allocator_->Adapter());
    auto &records = *info->records;

    const auto *pf = info->pf.get();
    for (auto id : pf->GetClasses()) {
        panda_file::File::EntityId classId(id);
        if (pf->IsExternal(classId)) {
            // Сlass that marked in currect .abc file as <external> should be define in some other .abc file.
            // Thus we will not lose information about this class.
            continue;
        }

        auto recordName = GetFullRecordName(*pf, classId);
        auto recordNameView = util::UString(recordName, allocator_).View();
        auto inserted = records.emplace(recordNameView, std::move(classId));
        // There should be only one declaration of the same class.
        ASSERT(inserted.second);
    }

    return records;
}

}  // namespace ark::es2panda::evaluate
