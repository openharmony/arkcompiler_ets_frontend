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

#ifndef CONVERT_EXPORT_H
#define CONVERT_EXPORT_H

#include "refactor_types.h"

namespace ark::es2panda::lsp {

constexpr RefactorActionView TO_NAMED_EXPORT_ACTION {"Convert default export to named export",
                                                     "Convert default export to named export",
                                                     "refactor.rewrite.export.named"};
constexpr RefactorActionView TO_DEFAULT_EXPORT_ACTION {"Convert named export to default export",
                                                       "Convert named export to default export",
                                                       "refactor.rewrite.export.default"};

class ConvertExportRefactor : public Refactor {
public:
    ConvertExportRefactor();
    ApplicableRefactorInfo GetAvailableActions(const RefactorContext &context) const override;
    std::unique_ptr<RefactorEditInfo> GetEditsForAction(const RefactorContext &context,
                                                        const std::string &actionName) const override;
};

}  // namespace ark::es2panda::lsp

#endif  // CONVERT_EXPORT_H
