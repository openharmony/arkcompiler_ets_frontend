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

#ifndef FIND_REFERENCES_H
#define FIND_REFERENCES_H

#include <vector>

#include "lexer/token/sourceLocation.h"
#include "es2panda.h"
#include "cancellation_token.h"

using PositionList = std::vector<ark::es2panda::lexer::SourcePosition>;
using FileRefMap = std::map<std::string, PositionList>;

namespace ark::es2panda::lsp {
// Returns a map of file path and reference position list
FileRefMap FindReferences(CancellationToken *tkn, const std::vector<SourceFile> &files, const SourceFile &file,
                          size_t position);
}  // namespace ark::es2panda::lsp

#endif