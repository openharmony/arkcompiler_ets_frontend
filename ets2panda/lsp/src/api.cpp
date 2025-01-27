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
#include "utils/arena_containers.h"

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
    FileReferences *result =
        allocator->New<FileReferences>(allocator->New<ArenaVector<FileReferenceInfo *>>(allocator->Adapter()));
    for (auto const &referenceFile : files) {
        auto referenceContext = initializer.CreateContext(referenceFile.c_str(), ES2PANDA_STATE_CHECKED);
        GetFileReferencesImpl(allocator, referenceContext, fileName, isPackageModule, result);
        initializer.DestroyContext(referenceContext);
    }

    return result;
}

extern "C" es2panda_AstNode *GetPrecedingToken(es2panda_Context *context, const size_t pos)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = ctx->parserProgram->Ast();
    return reinterpret_cast<es2panda_AstNode *>(FindPrecedingToken(pos, ast, ctx->allocator));
}

extern "C" std::string GetCurrentTokenValue(char const *fileName, size_t position)
{
    Initializer &initializer = Initializer::GetInstance();
    auto ctx = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto result = GetCurrentTokenValueImpl(ctx, position);
    initializer.DestroyContext(ctx);
    return result;
}

extern "C" TextSpan *GetSpanOfEnclosingComment(char const *fileName, size_t pos, bool onlyMultiLine)
{
    Initializer &initializer = Initializer::GetInstance();
    auto ctx = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto allocator = initializer.Allocator();
    auto range = GetRangeOfEnclosingComment(ctx, pos, allocator);
    initializer.DestroyContext(ctx);
    return (range != nullptr) && (!onlyMultiLine || range->GetKind() == CommentKind::MULTI_LINE)
               ? allocator->New<TextSpan>(range->GetPos(), range->GetEnd() - range->GetPos())
               : nullptr;
}

extern "C" ArenaVector<Diagnostic *> GetSemanticDiagnostics(char const *fileName)
{
    Initializer &initializer = Initializer::GetInstance();
    auto allocator = initializer.Allocator();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto semanticDiagnostics = GetSemanticDiagnosticsForFile(context, allocator);
    initializer.DestroyContext(context);
    return semanticDiagnostics;
}

LSPAPI g_lspImpl = {GetDefinitionAtPosition, GetFileReferences,         GetPrecedingToken,
                    GetCurrentTokenValue,    GetSpanOfEnclosingComment, GetSemanticDiagnostics};
}  // namespace ark::es2panda::lsp

LSPAPI const *GetImpl()
{
    return &ark::es2panda::lsp::g_lspImpl;
}
