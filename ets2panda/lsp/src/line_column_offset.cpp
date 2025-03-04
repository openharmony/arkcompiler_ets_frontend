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

#include "line_column_offset.h"
#include "public/es2panda_lib.h"
#include "public/public.h"
#include "internal_api.h"

namespace ark::es2panda::lsp {
const size_t NO_POS = 0;

LineAndCharacter ToLineColumnOffset(es2panda_Context *context, size_t position)
{
    if (position == NO_POS) {
        return LineAndCharacter(NO_POS, NO_POS);
    }

    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto node = lsp::GetTouchingToken(context, position, false);
    if (node == nullptr) {
        return LineAndCharacter(NO_POS, NO_POS);
    }

    auto program = ctx->parserProgram;
    lexer::LineIndex index(program->SourceCode());
    auto pos = node->Start();
    lexer::SourceLocation loc = index.GetLocation(pos);
    auto offset = index.GetOffset(loc);

    return LineAndCharacter(pos.line, offset);
}
}  // namespace ark::es2panda::lsp
