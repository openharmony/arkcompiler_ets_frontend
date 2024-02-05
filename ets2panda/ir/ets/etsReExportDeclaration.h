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

namespace ark::es2panda::ir {

class ETSReExportDeclaration {
public:
    explicit ETSReExportDeclaration(ETSImportDeclaration *const etsImportDeclarations,
                                    std::vector<std::string> const &userPaths, util::StringView programPath,
                                    ArenaAllocator *allocator)
        : etsImportDeclarations_(etsImportDeclarations), userPaths_(allocator->Adapter()), programPath_(programPath)
    {
        for (const auto &path : userPaths) {
            userPaths_.emplace_back(util::UString(path, allocator).View());
        }
    }

    ETSImportDeclaration *GetETSImportDeclarations() const
    {
        return etsImportDeclarations_;
    }

    ETSImportDeclaration *GetETSImportDeclarations()
    {
        return etsImportDeclarations_;
    }

    const ArenaVector<util::StringView> &GetUserPaths() const
    {
        return userPaths_;
    }

    util::StringView const &GetProgramPath() const
    {
        return programPath_;
    }

private:
    // NOTE(rsipka): this should use a singular name
    ETSImportDeclaration *etsImportDeclarations_;
    ArenaVector<util::StringView> userPaths_;
    util::StringView programPath_;
};
}  // namespace ark::es2panda::ir

#endif
