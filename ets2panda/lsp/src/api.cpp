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

#include "api.h"
#include "internal_api.h"
#include "public/es2panda_lib.h"
#include "public/public.h"
#include "util/options.h"

namespace ark::es2panda::lsp {

extern "C" DefinitionInfo *GetDefinitionAtPosition([[maybe_unused]] char const *fileName,
                                                   [[maybe_unused]] size_t position)
{
    return nullptr;
}

extern "C" FileReferences *GetFileReferences(char const *fileName)
{
    Initializer &initializer = Initializer::GetInstance();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    bool isPackageModule = reinterpret_cast<public_lib::Context *>(context)->parserProgram->IsPackage();
    auto options = reinterpret_cast<public_lib::Context *>(context)->config->options;
    auto files = options->ArkTSConfig()->Files();
    initializer.DestroyContext(context);

    auto allocator = initializer.Allocator();
    auto result = allocator->New<FileReferences>();
    for (auto const &referenceFile : files) {
        auto referenceContext = initializer.CreateContext(referenceFile.c_str(), ES2PANDA_STATE_CHECKED);
        GetFileReferencesImpl(allocator, referenceContext, fileName, isPackageModule, result);
        initializer.DestroyContext(referenceContext);
    }

    return result;
}

LSPAPI g_lspImpl = {
    GetDefinitionAtPosition,
    GetFileReferences,
};
}  // namespace ark::es2panda::lsp

LSPAPI const *GetImpl()
{
    return &ark::es2panda::lsp::g_lspImpl;
}
