/*
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

#include "lsp/include/api.h"
#include "common.h"

#include <cstddef>
#include <string>

KNativePointer impl_getCurrentTokenValue(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    return new std::string(ctx->getCurrentTokenValue(GetStringCopy(filenamePtr), static_cast<std::size_t>(position)));
}
TS_INTEROP_2(getCurrentTokenValue, KNativePointer, KStringPtr, KInt)

KNativePointer impl_getSyntacticDiagnostics(KStringPtr &filenamePtr)
{
    LSPAPI const *ctx = GetImpl();
    DiagnosticReferences *ptrDiag = new DiagnosticReferences(ctx->getSyntacticDiagnostics(GetStringCopy(filenamePtr)));
    return ptrDiag;
}
TS_INTEROP_1(getSyntacticDiagnostics, KNativePointer, KStringPtr)
