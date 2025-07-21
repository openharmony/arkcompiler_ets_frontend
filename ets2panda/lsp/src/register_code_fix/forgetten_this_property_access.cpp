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

#include "lsp/include/register_code_fix/forgetten_this_property_access.h"
#include <iostream>
#include <string>
#include "lsp/include/code_fix_provider.h"
#include "lsp/include/internal_api.h"

namespace ark::es2panda::lsp {

const int G_FORGETTEN_THIS_PROPERTY_ACCESS_CODE = 1004;  // change this to the error code you want to handle

ForgettenThisPropertyAccess::ForgettenThisPropertyAccess()
{
    const char *forgottenThisPropertAccesId = "ForgettenThisPropertyAccess";
    SetErrorCodes({G_FORGETTEN_THIS_PROPERTY_ACCESS_CODE});  // change this to the error code you want to handle
    SetFixIds({forgottenThisPropertAccesId});
}

std::vector<CodeFixAction> ForgettenThisPropertyAccess::GetCodeActions(const CodeFixContext &context)
{
    std::vector<CodeFixAction> returnedActions;
    if (context.errorCode == G_FORGETTEN_THIS_PROPERTY_ACCESS_CODE) {
    }
    return returnedActions;
}

CombinedCodeActions ForgettenThisPropertyAccess::GetAllCodeActions(const CodeFixAllContext &codeFixAll)
{
    CombinedCodeActions combinedCodeActions;
    if (codeFixAll.fixId == "ForgettenThisPropertyAccess") {
    }

    return combinedCodeActions;
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoCodeFixRegister<ForgettenThisPropertyAccess> g_forgettenThisPropertyAccess("ForgettenThisPropertyAccess");
}  // namespace ark::es2panda::lsp
