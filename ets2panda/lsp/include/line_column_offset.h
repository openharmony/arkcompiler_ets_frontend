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

#ifndef ES2PANDA_LSP_INCLUDE_LINE_COLUMN_OFFSET_H
#define ES2PANDA_LSP_INCLUDE_LINE_COLUMN_OFFSET_H

#include "public/es2panda_lib.h"
namespace ark::es2panda::lsp {
struct LineAndCharacter {
private:
    size_t line_;
    size_t character_;

public:
    explicit LineAndCharacter(size_t line, size_t character) : line_(line), character_(character) {}

    size_t GetLine() const
    {
        return line_;
    }
    size_t GetCharacter() const
    {
        return character_;
    }
};

LineAndCharacter ToLineColumnOffset(es2panda_Context *context, size_t position);
}  // namespace ark::es2panda::lsp
#endif  // ES2PANDA_LSP_INCLUDE_LINE_COLUMN_OFFSET_H
