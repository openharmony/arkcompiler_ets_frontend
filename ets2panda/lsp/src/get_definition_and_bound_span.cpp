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

#include "get_definition_and_bound_span.h"

namespace ark::es2panda::lsp {

/*
This api resolves the definition of a symbol at a given position in source code and returns:
The location of that definition (file + span)
The text span in the original file where the symbol is referenced (to highlight or navigate)
*/
DefinitionInfoAndBoundSpan GetDefinitionAndBoundSpan(es2panda_Context *referenceFileContext, size_t offset)
{
    LSPAPI const *lspApi = GetImpl();
    auto ctx = reinterpret_cast<public_lib::Context *>(referenceFileContext);
    auto statements = ctx->parserProgram->Ast()->Statements();
    const auto definitions = lspApi->getDefinitionAtPosition(referenceFileContext, offset);
    const auto node = GetTouchingPropertyName(referenceFileContext, offset);
    if (node == nullptr) {
        return {};
    }
    const auto textSpan = CreateTextSpanForNode(node);

    return {definitions, textSpan};
}

}  // namespace ark::es2panda::lsp