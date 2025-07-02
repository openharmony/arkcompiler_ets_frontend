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

#ifndef APPLICABLE_REFACTORS_H
#define APPLICABLE_REFACTORS_H

#include "public/es2panda_lib.h"
#include <string>
#include <string_view>
#include <vector>

namespace ark::es2panda::lsp {

using RefactorActionView = struct RefactorActionView {
    std::string_view name;
    std::string_view description;
    std::string_view kind;
};

using RefactorAction = struct RefactorAction {
    std::string name;
    std::string description;
    std::string kind;
};

using ApplicableRefactorInfo = struct ApplicableRefactorInfo {
    std::string name;
    std::string description;
    RefactorAction action;
};

namespace refactor_name {
constexpr std::string_view CONVERT_FUNCTION_REFACTOR_NAME = "Convert arrow function or function expression";
}  // namespace refactor_name

namespace refactor_description {
constexpr std::string_view CONVERT_FUNCTION_REFACTOR_DESC = "Convert arrow function or function expression";
}  // namespace refactor_description

class Refactor {
private:
    std::vector<std::string> kinds_;

public:
    bool IsKind(const std::string &kind);
    void AddKind(const std::string &kind);
    virtual ApplicableRefactorInfo GetAvailableActions(es2panda_Context *context, std::string kind,
                                                       size_t position) = 0;
    virtual ~Refactor() = default;
    Refactor() = default;
    Refactor &operator=(const Refactor &other);
    Refactor &operator=(Refactor &&other);
    Refactor(const Refactor &other);
    Refactor(Refactor &&other);
};

ApplicableRefactorInfo GetApplicableRefactorsImpl(es2panda_Context *context, const char *kind, size_t position);
}  // namespace ark::es2panda::lsp

#endif  // APPLICABLE_REFACTORS_H