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

#include "internal_api.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

ir::AstNode *GetTouchingToken(es2panda_Context *context, size_t pos, bool flagFindFirstMatch)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    auto checkFunc = [&pos](ir::AstNode *node) { return pos >= node->Start().index && pos < node->End().index; };
    auto found = ast->FindChild(checkFunc);
    while (found != nullptr && !flagFindFirstMatch) {
        auto *nestedFound = found->FindChild(checkFunc);
        if (nestedFound == nullptr) {
            break;
        }
        found = nestedFound;
    }
    return found;
}

}  // namespace ark::es2panda::lsp
