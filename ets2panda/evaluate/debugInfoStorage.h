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

#ifndef ES2PANDA_EVALUATE_DEBUG_INFO_STORAGE_H
#define ES2PANDA_EVALUATE_DEBUG_INFO_STORAGE_H

#include "evaluate/evaluateContext.h"
#include "util/ustring.h"

#include "libpandabase/utils/arena_containers.h"
#include "libpandafile/debug_info_extractor.h"
#include "libpandafile/file.h"
#include "libpandafile/class_data_accessor.h"

#include <memory>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace ark::es2panda::evaluate {

struct EntityInfo final {
    EntityInfo(std::string_view path, std::string_view entity) : filePath(path), entityName(entity) {}

    std::string_view filePath;
    std::string_view entityName;
};

class ImportExportTable final {
public:
    using AliasMap = ArenaUnorderedMap<std::string_view, ArenaVector<EntityInfo>>;

public:
    explicit ImportExportTable(ArenaAllocator *allocator);

    const AliasMap &GetImports() const
    {
        return imports_;
    }

    const AliasMap &GetExports() const
    {
        return exports_;
    }

private:
    AliasMap imports_;
    AliasMap exports_;
};

// Context-independent debug info lazy-loading storage.
// All "find" methods must accept paths to source files.
class DebugInfoStorage final {
public:
    explicit DebugInfoStorage(const CompilerOptions &options, ArenaAllocator *allocator);

    NO_COPY_SEMANTIC(DebugInfoStorage);
    NO_MOVE_SEMANTIC(DebugInfoStorage);

    ~DebugInfoStorage() = default;

    [[nodiscard]] bool FillEvaluateContext(EvaluateContext &context);

    const panda_file::File *GetPandaFile(std::string_view filePath);
    const ImportExportTable *GetImportExportTable(std::string_view filePath);
    panda_file::ClassDataAccessor *GetGlobalClassAccessor(std::string_view filePath);
    std::string_view GetModuleName(std::string_view filePath);

    /**
     * @brief Returns import path on success, empty string otherwise
     */
    std::string_view FindNamedImportAll(std::string_view filePath, std::string_view bindingName);

    std::optional<EntityInfo> FindImportedEntity(std::string_view filePath, std::string_view entityName);
    void FindImportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                               std::string_view entityName);

    /**
     * @brief Returns class'es panda file Id on success, invalid EntityId otherwise
     */
    panda_file::File::EntityId FindClass(std::string_view filePath, std::string_view className);

    template <typename Callback>
    void EnumerateContextFiles(const Callback &cb)
    {
        for (const auto &[sourceFilePath, debugInfo] : sourceFileToDebugInfo_) {
            if (!cb(sourceFilePath, debugInfo->pf.get(), debugInfo->globalClassAcc,
                    std::string_view(debugInfo->moduleName))) {
                return;
            }
        }
    }

private:
    struct FileDebugInfo final {
        using RecordsMap = ArenaUnorderedMap<util::StringView, panda_file::File::EntityId>;

        FileDebugInfo() = delete;
        explicit FileDebugInfo(std::unique_ptr<const panda_file::File> &&pandaFile, panda_file::ClassDataAccessor &&cda,
                               std::string &&module)
            : pf(std::move(pandaFile)), globalClassAcc(std::move(cda)), moduleName(std::move(module))
        {
            ASSERT(pf);
        }

        std::unique_ptr<const panda_file::File> pf {nullptr};
        panda_file::ClassDataAccessor globalClassAcc;
        std::string moduleName;
        std::optional<ImportExportTable> importExportTable;
        std::optional<RecordsMap> records;
    };

    using DebugInfoMap = ArenaUnorderedMap<std::string_view, FileDebugInfo *>;

private:
    void LoadFileDebugInfo(std::string_view pfPath);

    const ImportExportTable &LazyLoadImportExportTable(FileDebugInfo *info);
    const FileDebugInfo::RecordsMap &LazyLoadRecords(FileDebugInfo *info);

    std::optional<EntityInfo> FindExportedEntity(std::string_view filePath, std::string_view entityName);
    void FindExportedFunctions(ArenaVector<EntityInfo> &overloadSet, std::string_view filePath,
                               std::string_view entityName);

private:
    static constexpr std::string_view STAR_IMPORT = "*";

    ArenaAllocator *allocator_;

    // Mapping from sources' files names into the corresponding debug information struct.
    // Used for fast lookups basing on imports/exports tables.
    DebugInfoMap sourceFileToDebugInfo_;
    // Mapping from module names into the corresponding debug information struct.
    // Used for fast lookups during inheritance chain resolution.
    DebugInfoMap moduleNameToDebugInfo_;
};

}  // namespace ark::es2panda::evaluate

#endif  // ES2PANDA_EVALUATE_DEBUG_INFO_STORAGE_H
