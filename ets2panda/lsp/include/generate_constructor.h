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

#ifndef GENERATE_CONSTRUCTOR_H
#define GENERATE_CONSTRUCTOR_H

#include "api.h"
#include <vector>
#include <string>
#include "user_preferences.h"
#include "ir/astNode.h"
#include "es2panda.h"

namespace ark::es2panda::lsp {

std::vector<FileTextChanges> GetRefactorActionsToGenerateConstructor(es2panda_Context *context, size_t position,
                                                                     const std::vector<std::string> &properties);

}  // namespace ark::es2panda::lsp
#endif