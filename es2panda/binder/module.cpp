/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "module.h"

#include <binder/scope.h>

namespace panda::es2panda::binder {

    int SourceTextModuleRecord::AddModuleRequest(const util::StringView source, lexer::SourcePosition sourcePos)
    {
        ASSERT(!source.Empty());
        int moduleRequestsSize = static_cast<int>(moduleRequestsMap_.size());
        if (moduleRequestsMap_.find(source) == moduleRequestsMap_.end()) {
            moduleRequests_.emplace_back(source);
        }
        auto insertedRes = moduleRequestsMap_.insert(
            std::make_pair(source, ModuleRequest(moduleRequestsSize, sourcePos.index))
        );
        return insertedRes.first->second.idx;
    }

    void SourceTextModuleRecord::AddImportEntry(const util::StringView importName,
                                                const util::StringView localName,
                                                const util::StringView moduleRequest,
                                                const lexer::SourcePosition pos,
                                                const lexer::SourcePosition sourcePos)
    {
        auto *importEntry = allocator_->New<SourceTextModuleRecord::Entry>(pos);
        importEntry->importName = importName;
        importEntry->localName = localName;
        importEntry->moduleRequest = AddModuleRequest(moduleRequest, sourcePos);
        ASSERT(!importEntry->importName.Empty());
        ASSERT(!importEntry->localName.Empty());
        ASSERT(importEntry->exportName.Empty());
        ASSERT(importEntry->moduleRequest != -1);
        regularImportEntries_.insert(std::make_pair(importEntry->localName, importEntry));
    }

    void SourceTextModuleRecord::AddEmptyImportEntry(const util::StringView moduleRequest,
                                                     const lexer::SourcePosition sourcePos)
    {
        AddModuleRequest(moduleRequest, sourcePos);
    }

    void SourceTextModuleRecord::AddStarImportEntry(const ir::AstNode *moduleNode,
                                                    const util::StringView localName,
                                                    const util::StringView moduleRequest,
                                                    const lexer::SourcePosition pos,
                                                    const lexer::SourcePosition sourcePos)
    {
        auto *starImportEntry = allocator_->New<SourceTextModuleRecord::Entry>(pos);
        starImportEntry->moduleNode = moduleNode;
        starImportEntry->localName = localName;
        starImportEntry->moduleRequest = AddModuleRequest(moduleRequest, sourcePos);
        ASSERT(starImportEntry->moduleNode != nullptr);
        ASSERT(starImportEntry->importName.Empty());
        ASSERT(!starImportEntry->localName.Empty());
        ASSERT(starImportEntry->exportName.Empty());
        ASSERT(starImportEntry->moduleRequest != -1);
        namespaceImportEntries_.push_back(starImportEntry);
    }

    void SourceTextModuleRecord::AddLocalExportEntry(const util::StringView exportName,
                                                     const util::StringView localName,
                                                     const lexer::SourcePosition pos)
    {
        auto *localExportEntry = allocator_->New<SourceTextModuleRecord::Entry>(pos);
        localExportEntry->exportName = exportName;
        localExportEntry->localName = localName;
        ASSERT(localExportEntry->importName.Empty());
        ASSERT(!localExportEntry->localName.Empty());
        ASSERT(!localExportEntry->exportName.Empty());
        ASSERT(localExportEntry->moduleRequest == -1);
        localExportEntries_.insert(std::make_pair(localExportEntry->localName, localExportEntry));
    }

    void SourceTextModuleRecord::AddIndirectExportEntry(const util::StringView importName,
                                                        const util::StringView exportName,
                                                        const util::StringView moduleRequest,
                                                        const lexer::SourcePosition pos,
                                                        const lexer::SourcePosition sourcePos)
    {
        auto *indirectExportEntry = allocator_->New<SourceTextModuleRecord::Entry>(pos);
        indirectExportEntry->importName = importName;
        indirectExportEntry->exportName = exportName;
        indirectExportEntry->moduleRequest = AddModuleRequest(moduleRequest, sourcePos);
        ASSERT(!indirectExportEntry->importName.Empty());
        ASSERT(indirectExportEntry->localName.Empty());
        ASSERT(!indirectExportEntry->exportName.Empty());
        ASSERT(indirectExportEntry->moduleRequest != -1);
        indirectExportEntries_.push_back(indirectExportEntry);
    }

    void SourceTextModuleRecord::AddStarExportEntry(const util::StringView moduleRequest,
                                                    const lexer::SourcePosition pos,
                                                    const lexer::SourcePosition sourcePos)
    {
        auto *starExportEntry = allocator_->New<SourceTextModuleRecord::Entry>(pos);
        starExportEntry->moduleRequest = AddModuleRequest(moduleRequest, sourcePos);
        ASSERT(starExportEntry->importName.Empty());
        ASSERT(starExportEntry->localName.Empty());
        ASSERT(starExportEntry->exportName.Empty());
        ASSERT(starExportEntry->moduleRequest != -1);
        starExportEntries_.push_back(starExportEntry);
    }

    const SourceTextModuleRecord::Entry *SourceTextModuleRecord::NextDuplicateExportEntry(
        const Entry *entry,
        const Entry *duplicate,
        ArenaMap<const util::StringView, const SourceTextModuleRecord::Entry *> &exportNameEntries)
    {
        ASSERT(!entry->exportName.Empty());
        auto insertRes = exportNameEntries.insert(std::make_pair(entry->exportName, entry));

        // successfully inserted when there has no duplicate entry
        if (insertRes.second) {
            return duplicate;
        }

        // find [entry] has same export name with one of the exportNameEntries
        if (duplicate == nullptr) {
            // update duplicate entry if pre duplicate is null
            duplicate = insertRes.first->second;
        }

        // return the entry at the backward position
        if (entry->position.index > duplicate->position.index) {
            return entry;
        }

        return duplicate;
    }

    const SourceTextModuleRecord::Entry *SourceTextModuleRecord::SearchDupExport()
    {
        const SourceTextModuleRecord::Entry *duplicateEntry = nullptr;
        ArenaMap<const util::StringView, const SourceTextModuleRecord::Entry *> exportNameEntries(
            allocator_->Adapter());

        for (auto const &entryUnit : localExportEntries_) {
            duplicateEntry = NextDuplicateExportEntry(entryUnit.second, duplicateEntry, exportNameEntries);
        }

        for (auto entry : indirectExportEntries_) {
            duplicateEntry = NextDuplicateExportEntry(entry, duplicateEntry, exportNameEntries);
        }

        return duplicateEntry;
    }

    bool SourceTextModuleRecord::ValidateModuleRecordEntries(ModuleScope *moduleScope,
                                                             std::string &errorMessage,
                                                             lexer::SourcePosition &errorPos)
    {
        ASSERT(this == moduleScope->GetModuleRecord());
        const SourceTextModuleRecord::Entry *dupExportEntry = SearchDupExport();
        if (dupExportEntry != nullptr) {
            errorMessage.append("Duplicate export name of '" + dupExportEntry->exportName.Mutf8() + "'");
            errorPos.index = dupExportEntry->position.index;
            errorPos.line = dupExportEntry->position.line;
            return false;
        }

        for (const auto &entryUnit : localExportEntries_) {
            const SourceTextModuleRecord::Entry *e = entryUnit.second;
            ASSERT(!e->exportName.Empty());
            if (moduleScope->FindLocal(e->localName) == nullptr && !e->localName.Is("*default*")) {
                errorMessage.append("Export name '" + e->localName.Mutf8() + "' is not defined");
                errorPos.index = e->position.index;
                errorPos.line = e->position.line;
                return false;
            }
        }

        /*
         * Translate implicit indirectExport entry into explicit entry
         * e.g. import { x } from 'test.js'; export { x }
         *      --->
         *      import { x } from 'test.js'; export { x } from 'test.js';
         */
        for (auto it = localExportEntries_.begin(); it != localExportEntries_.end();) {
            auto exportEntry = it->second;
            ASSERT(!exportEntry->localName.Empty());
            auto importEntry = regularImportEntries_.find(exportEntry->localName);
            if (importEntry != regularImportEntries_.end()) {
                ASSERT(exportEntry->importName.Empty());
                ASSERT(exportEntry->moduleRequest == -1);
                ASSERT(!importEntry->second->importName.Empty());
                ASSERT(importEntry->second->moduleRequest != -1);
                exportEntry->importName = importEntry->second->importName;
                exportEntry->moduleRequest = importEntry->second->moduleRequest;
                exportEntry->localName = util::StringView("");
                exportEntry->position = importEntry->second->position;
                indirectExportEntries_.push_back(exportEntry);
                it = localExportEntries_.erase(it);
                continue;
            }
            ++it;
        }
        return true;
    }

    void SourceTextModuleRecord::SetLocalExportEntriesVariables(ModuleScope *moduleScope)
    {
        for (auto it = localExportEntries_.begin();
             it != localExportEntries_.end();
             it = localExportEntries_.upper_bound(it->first)) {
            moduleScope->SetVariableAsExported(allocator_, it->first);
        }
    }

    void SourceTextModuleRecord::SetNameSpaceImportInitialized(ModuleScope *moduleScope)
    {
        for (auto namespaceEntry : namespaceImportEntries_) {
            auto *var = moduleScope->FindLocal(namespaceEntry->localName);
            ASSERT(var != nullptr);
            var->AddFlag(VariableFlags::INITIALIZED);
        }
    }

    void SourceTextModuleRecord::SetModuleEnvironment(ModuleScope *moduleScope)
    {
        SetNameSpaceImportInitialized(moduleScope);
        SetLocalExportEntriesVariables(moduleScope);
    }
} // namespace panda::es2panda::binder