/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GET_CLASS_PROPERTY_INFO_H
#define GET_CLASS_PROPERTY_INFO_H

#include <cstddef>
#include <string>
#include <tuple>
#include <vector>

#include "ast_verifier/helpers.h"
#include "cancellation_token.h"
#include "es2panda.h"
#include "class_hierarchy.h"
#include "api.h"
#include "internal_api.h"
#include "public/public.h"
#include "types.h"

namespace ark::es2panda::lsp {
// NOLINTBEGIN(misc-non-private-member-variables-in-classes)
struct InstallPackageAction {
    std::string type;
    std::optional<std::string> file;
    std::optional<std::string> packageName;

    InstallPackageAction() : type("install package") {}
};

using CodeActionCommand = InstallPackageAction;

struct RefactorEditInfoes {
    std::vector<FileTextChanges> edits;
    std::optional<std::string> renameFilename;
    std::optional<int> renameNumber;
    std::optional<std::vector<CodeActionCommand>> commands;
};

// NOLINTEND(misc-non-private-member-variables-in-classes)
/**
 * @brief Get class property info at position, optionally including inherited.
 * @param context           Parser context (es2panda_Context*).
 * @param pos               Position to locate class declaration.
 * @param shouldCollectInherited  Collect inherited properties if true (default: false).
 * @return Vector of FieldsInfo. Empty if context/position invalid or class not found.
 */
std::vector<FieldsInfo> GetClassPropertyInfo(es2panda_Context *context, size_t pos,
                                             bool shouldCollectInherited = false);
}  // namespace ark::es2panda::lsp

#endif