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

#include "brace_matching.h"
#include <cstddef>
#include "public/public.h"

namespace ark::es2panda::lsp {
bool CheckNodeKindForBraceMatching(ark::es2panda::ir::AstNode *node)
{
    switch (node->Type()) {
        case ark::es2panda::ir::AstNodeType::BLOCK_STATEMENT:
        case ark::es2panda::ir::AstNodeType::ARRAY_EXPRESSION:
        case ark::es2panda::ir::AstNodeType::ETS_TUPLE:
        case ark::es2panda::ir::AstNodeType::TS_TYPE_PARAMETER_INSTANTIATION:
        case ark::es2panda::ir::AstNodeType::TS_TYPE_PARAMETER_DECLARATION:
            return true;
        default:
            return false;
    }
}

std::vector<TextSpan> GetBraceMatchingAtPosition(es2panda_Context *context, size_t position)
{
    auto token = GetTouchingToken(context, position, false);
    if (token == nullptr) {
        return {};
    }

    if (CheckNodeKindForBraceMatching(token) && token->Start().index == position) {
        TextSpan startSpan(token->Start().index, token->End().index - token->Start().index);
        TextSpan endSpan(token->End().index, token->End().index - token->Start().index);

        std::vector<TextSpan> spans = {startSpan, endSpan};
        return spans;
    }
    return {};
}
}  // namespace ark::es2panda::lsp