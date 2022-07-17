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

#ifndef ES2PANDA_COMPILER_SCOPES_MODULE_H
#define ES2PANDA_COMPILER_SCOPES_MODULE_H

#include <lexer/token/sourceLocation.h>
#include <util/ustring.h>

namespace panda::es2panda::ir {
class AstNode;
} // namespace panda::es2panda::ir

namespace panda::es2panda::binder {

class ModuleScope;

class SourceTextModuleRecord {
    public:
        explicit SourceTextModuleRecord(ArenaAllocator *allocator)
            : allocator_(allocator),
              moduleRequestsMap_(allocator_->Adapter()),
              moduleRequests_(allocator_->Adapter()),
              localExportEntries_(allocator_->Adapter()),
              regularImportEntries_(allocator_->Adapter()),
              namespaceImportEntries_(allocator_->Adapter()),
              starExportEntries_(allocator_->Adapter()),
              indirectExportEntries_(allocator_->Adapter())
        {
        }

        ~SourceTextModuleRecord() = default;
        NO_COPY_SEMANTIC(SourceTextModuleRecord);
        NO_MOVE_SEMANTIC(SourceTextModuleRecord);

        struct Entry {
            lexer::SourcePosition position;
            const ir::AstNode *moduleNode;
            int moduleRequest;
            util::StringView exportName;
            util::StringView localName;
            util::StringView importName;

            explicit Entry(lexer::SourcePosition pos)
                : position(pos),
                  moduleNode(nullptr),
                  moduleRequest(-1) {}
        };

        struct ModuleRequest {
            int idx;
            int pos;
            ModuleRequest(int idx, int pos)
                : idx(idx), pos(pos) {}
        };

        // import x from 'test.js';
        // import {x} from 'test.js';
        // import {x as y} from 'test.js';
        // import defaultExport from 'test.js'
        void AddImportEntry(const util::StringView importName,
                            const util::StringView localName,
                            const util::StringView moduleRequest,
                            const lexer::SourcePosition pos,
                            const lexer::SourcePosition sourcePos);

        // import 'test.js'
        // import {} from 'test.js'
        // export {} from 'test.js'
        void AddEmptyImportEntry(const util::StringView moduleRequest, const lexer::SourcePosition sourcePos);

        // import * as x from 'test.js';
        void AddStarImportEntry(const ir::AstNode *moduleNode,
                                const util::StringView localName,
                                const util::StringView moduleRequest,
                                const lexer::SourcePosition pos,
                                const lexer::SourcePosition sourcePos);

        // export {x};
        // export {x as y};
        // export VariableStatement
        // export Declaration
        // export default ...
        void AddLocalExportEntry(const util::StringView exportName,
                                 const util::StringView localName,
                                 const lexer::SourcePosition pos);

        // export {x} from 'test.js';
        // export {x as y} from 'test.js';
        // import { x } from 'test.js'; export { x }
        void AddIndirectExportEntry(const util::StringView importName,
                                    const util::StringView exportName,
                                    const util::StringView moduleRequest,
                                    const lexer::SourcePosition pos,
                                    const lexer::SourcePosition sourcePos);

        // export * from 'test.js';
        void AddStarExportEntry(const util::StringView moduleRequest,
                                const lexer::SourcePosition pos,
                                const lexer::SourcePosition sourcePos);
        
        bool ValidateModuleRecordEntries(ModuleScope *moduleScope,
                                         std::string &errorMessage,
                                         lexer::SourcePosition &errorPos);

        void SetModuleEnvironment(ModuleScope *moduleScope);

        using ModuleRequestMap = ArenaMap<const util::StringView, ModuleRequest>;
        using LocalExportEntryMap = ArenaMultiMap<const util::StringView, Entry *>;
        using RegularImportEntryMap = ArenaMap<const util::StringView, Entry *>;

        const ArenaVector<util::StringView> &GetModuleRequests() const
        {
            return moduleRequests_;
        }

        const LocalExportEntryMap &GetLocalExportEntries() const
        {
            return localExportEntries_;
        }

        const RegularImportEntryMap &GetRegularImportEntries() const
        {
            return regularImportEntries_;
        }

        const ArenaVector<const Entry *> &GetNamespaceImportEntries() const
        {
            return namespaceImportEntries_;
        }

        const ArenaVector<const Entry *> &GetStarExportEntries() const
        {
            return starExportEntries_;
        }

        const ArenaVector<const Entry *> &GetIndirectExportEntries() const
        {
            return indirectExportEntries_;
        }

    private:
        int AddModuleRequest(const util::StringView source, lexer::SourcePosition sourcePos);
        void SetLocalExportEntriesVariables(ModuleScope *moduleScope);
        void SetNameSpaceImportInitialized(ModuleScope *moduleScope);

        const Entry *SearchDupExport();

        const Entry *NextDuplicateExportEntry(const Entry *entry,
                                              const Entry *duplicate,
                                              ArenaMap<const util::StringView, const Entry *> &exportNameEntries);

        ArenaAllocator *allocator_;
        ModuleRequestMap moduleRequestsMap_;
        ArenaVector<util::StringView> moduleRequests_;
        LocalExportEntryMap localExportEntries_;
        RegularImportEntryMap regularImportEntries_;
        ArenaVector<const Entry *> namespaceImportEntries_;
        ArenaVector<const Entry *> starExportEntries_;
        ArenaVector<const Entry *> indirectExportEntries_;
};

} // namespace panda::es2panda::binder
#endif