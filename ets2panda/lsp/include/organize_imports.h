/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_LSP_ORGANIZE_IMPORTS_H
#define ES2PANDA_LSP_ORGANIZE_IMPORTS_H

#include <string>
#include <vector>
#include "public/es2panda_lib.h"

struct FileTextChanges;

namespace ark::es2panda::lsp {

enum class ImportType { NORMAL, DEFAULT, NAMESPACE, TYPE_ONLY };

struct ImportSpecifier {
    std::string importedName;
    std::string localName;
    ImportType type;
    size_t start;
    size_t length;
};

struct ImportInfo {
    std::string moduleName;
    std::vector<ImportSpecifier> namedImports;
    size_t startIndex;
    size_t endIndex;
};

struct OrganizeImports {
    static std::vector<FileTextChanges> Organize(es2panda_Context *context, const std::string &fileName);
};

}  // namespace ark::es2panda::lsp

#endif
