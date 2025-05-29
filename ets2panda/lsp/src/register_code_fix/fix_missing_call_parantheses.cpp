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

#include "lsp/include/register_code_fix/fix_missing_call_parantheses.h"
#include <iostream>
#include "lsp/include/code_fix_provider.h"
#include "lsp/include/internal_api.h"

namespace ark::es2panda::lsp {
const int G_FIX_MISSING_CALL_PARANTHESES_CODE = 1002;  // change this to the error code you want to handle

FixMissingCallParantheses::FixMissingCallParantheses()
{
    const char *fixMissingCallParanthesesId = "FixMissingCallParantheses";

    SetErrorCodes({G_FIX_MISSING_CALL_PARANTHESES_CODE});  // change this to the error code you want to handle
    SetFixIds({fixMissingCallParanthesesId});
}

std::vector<CodeFixAction> FixMissingCallParantheses::GetCodeActions(const CodeFixContext &context)
{
    std::vector<CodeFixAction> returnedActions;
    if (context.errorCode == G_FIX_MISSING_CALL_PARANTHESES_CODE) {
    }
    return returnedActions;
}

CombinedCodeActions FixMissingCallParantheses::GetAllCodeActions(const CodeFixAllContext &codeFixAll)
{
    CombinedCodeActions combinedCodeActions;
    if (codeFixAll.fixId == "FixMissingCallParantheses") {
    }

    return combinedCodeActions;
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoCodeFixRegister<FixMissingCallParantheses> g_fixMissingCallParantheses("FixMissingCallParantheses");
}  // namespace ark::es2panda::lsp
