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

#ifndef ES2PANDA_IR_ETS_RE_EXPORT_DECLARATION_H
#define ES2PANDA_IR_ETS_RE_EXPORT_DECLARATION_H

#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsImportSource.h"
#include "ir/module/importDeclaration.h"
#include "varbinder/varbinder.h"

namespace panda::es2panda::ir {

class ETSReExportDeclaration {
public:
    explicit ETSReExportDeclaration(ETSImportDeclaration *const ets_import_declarations,
                                    std::vector<std::string> const &user_paths, util::StringView program_path,
                                    ArenaAllocator *allocator)
        : ets_import_declarations_(ets_import_declarations),
          user_paths_(allocator->Adapter()),
          program_path_(program_path)
    {
        for (const auto &path : user_paths) {
            user_paths_.emplace_back(util::UString(path, allocator).View());
        }
    }

    ETSImportDeclaration *GetETSImportDeclarations() const
    {
        return ets_import_declarations_;
    }

    ETSImportDeclaration *GetETSImportDeclarations()
    {
        return ets_import_declarations_;
    }

    const ArenaVector<util::StringView> &GetUserPaths() const
    {
        return user_paths_;
    }

    util::StringView const &GetProgramPath() const
    {
        return program_path_;
    }

private:
    ETSImportDeclaration *ets_import_declarations_;
    ArenaVector<util::StringView> user_paths_;
    util::StringView program_path_;
};
}  // namespace panda::es2panda::ir

#endif
