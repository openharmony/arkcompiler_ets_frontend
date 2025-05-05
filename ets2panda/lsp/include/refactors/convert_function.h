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

#ifndef CONVERT_FUNCTION_H
#define CONVERT_FUNCTION_H

#include "lsp/include/applicable_refactors.h"

namespace ark::es2panda::lsp {

constexpr RefactorActionView TO_ANONYMOUS_FUNCTION_ACTION {
    "Convert to anonymous function", "Convert to anonymous function", "refactor.rewrite.function.anonymous"};
constexpr RefactorActionView TO_NAMED_FUNCTION_ACTION {"Convert to named function", "Convert to named function",
                                                       "refactor.rewrite.function.named"};
constexpr RefactorActionView TO_ARROW_FUNCTION_ACTION {"Convert to arrow function", "Convert to arrow function",
                                                       "refactor.rewrite.function.arrow"};

class ConvertFunctionRefactor : public Refactor {
public:
    ConvertFunctionRefactor();
    ApplicableRefactorInfo GetAvailableActions(es2panda_Context *context, std::string kind, size_t position) override;
};
}  // namespace ark::es2panda::lsp

#endif  // CONVERT_FUNCTION_H