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
#include <cstddef>
#include <vector>
#include "internal_api.h"
#include "references.h"
#include "public/es2panda_lib.h"
#include "cancellation_token.h"
#include "public/public.h"
#include "util/options.h"
#include "quick_info.h"

namespace ark::es2panda::lsp {

extern "C" DefinitionInfo *GetDefinitionAtPosition([[maybe_unused]] char const *fileName,
                                                   [[maybe_unused]] size_t position)
{
    return nullptr;
}

extern "C" References GetFileReferences(char const *fileName)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    bool isPackageModule = reinterpret_cast<public_lib::Context *>(context)->parserProgram->IsPackage();
    auto options = reinterpret_cast<public_lib::Context *>(context)->config->options;
    auto compilationList = FindProjectSources(options->ArkTSConfig());
    initializer.DestroyContext(context);

    auto result = References();
    for (auto const &referenceFile : compilationList) {
        auto referenceContext = initializer.CreateContext(referenceFile.first.c_str(), ES2PANDA_STATE_CHECKED);
        GetFileReferencesImpl(referenceContext, fileName, isPackageModule, &result);
        initializer.DestroyContext(referenceContext);
    }
    return result;
}

extern "C" References GetReferencesAtPosition(char const *fileName, size_t position)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto options = reinterpret_cast<public_lib::Context *>(context)->config->options;
    auto compilationList = FindProjectSources(options->ArkTSConfig());
    auto astNode = GetTouchingToken(context, position, false);
    auto declInfo = GetDeclInfo(astNode);
    initializer.DestroyContext(context);

    References result;
    for (auto const &file : compilationList) {
        auto fileContext = initializer.CreateContext(file.first.c_str(), ES2PANDA_STATE_CHECKED);
        GetReferencesAtPositionImpl(fileContext, declInfo, &result);
        initializer.DestroyContext(fileContext);
    }

    auto compare = [](const ReferenceInfo &lhs, const ReferenceInfo &rhs) {
        if (lhs.fileName != rhs.fileName) {
            return lhs.fileName < rhs.fileName;
        }
        if (lhs.start != rhs.start) {
            return lhs.start < rhs.start;
        }
        return lhs.length < rhs.length;
    };
    RemoveDuplicates(result.referenceInfos, compare);
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
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto result = GetCurrentTokenValueImpl(ctx, position);
    initializer.DestroyContext(ctx);
    return result;
}

extern "C" QuickInfo GetQuickInfoAtPosition(const char *fileName, size_t position)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto res = GetQuickInfoAtPositionImpl(context, position, fileName);
    initializer.DestroyContext(context);
    return res;
}

extern "C" TextSpan GetSpanOfEnclosingComment(char const *fileName, size_t pos, bool onlyMultiLine)
{
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto *range = initializer.Allocator()->New<CommentRange>();
    GetRangeOfEnclosingComment(ctx, pos, range);
    initializer.DestroyContext(ctx);
    return (range != nullptr) && (!onlyMultiLine || range->kind_ == CommentKind::MULTI_LINE)
               ? TextSpan(range->pos_, range->end_ - range->pos_)
               : TextSpan(0, 0);
}

extern "C" DiagnosticReferences GetSemanticDiagnostics(char const *fileName)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    DiagnosticReferences result {};
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    const auto &diagnostics = ctx->diagnosticEngine->GetDiagnosticStorage(util::DiagnosticType::SEMANTIC);
    for (const auto &diagnostic : diagnostics) {
        result.diagnostic.push_back(CreateDiagnosticForError(context, *diagnostic));
    }
    initializer.DestroyContext(context);
    return result;
}

extern "C" DiagnosticReferences GetSyntacticDiagnostics(char const *fileName)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    DiagnosticReferences result {};
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    const auto &diagnostics = ctx->diagnosticEngine->GetDiagnosticStorage(util::DiagnosticType::SYNTAX);
    for (const auto &diagnostic : diagnostics) {
        result.diagnostic.push_back(CreateDiagnosticForError(context, *diagnostic));
    }
    initializer.DestroyContext(context);
    return result;
}

extern "C" ReferenceLocationList GetReferenceLocationAtPosition(char const *fileName, size_t pos,
                                                                const std::vector<std::string> &autoGenerateFolders,
                                                                CancellationToken cancellationToken)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    if (context == nullptr) {
        return {};
    }

    auto options = reinterpret_cast<public_lib::Context *>(context)->config->options;

    auto files = options->ArkTSConfig()->Files();
    if (files.empty()) {
        return {};
    }

    RemoveFromFiles(files, autoGenerateFolders);

    auto node = GetTouchingToken(context, pos, false);
    if (node == nullptr) {
        return {};
    }

    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    FileNodeInfo fileNameInfo(tokenName, tokenId);
    auto list = ReferenceLocationList();
    initializer.DestroyContext(context);
    for (const std::string &file : files) {
        if (cancellationToken.IsCancellationRequested()) {
            return list;
        }
        auto ctx = initializer.CreateContext(file.c_str(), ES2PANDA_STATE_CHECKED);
        ark::es2panda::lsp::GetReferenceLocationAtPositionImpl(fileNameInfo, ctx, &list);
        initializer.DestroyContext(ctx);
    }
    return list;
}

extern "C" DocumentHighlightsReferences GetDocumentHighlights(char const *fileName, size_t position)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    DocumentHighlightsReferences result = {};
    result.documentHighlights_.push_back(GetDocumentHighlightsImpl(context, position));
    initializer.DestroyContext(context);
    return result;
}

LSPAPI g_lspImpl = {GetDefinitionAtPosition,   GetFileReferences,
                    GetReferencesAtPosition,   GetPrecedingToken,
                    GetCurrentTokenValue,      GetQuickInfoAtPosition,
                    GetSpanOfEnclosingComment, GetSemanticDiagnostics,
                    GetSyntacticDiagnostics,   GetReferenceLocationAtPosition,
                    GetDocumentHighlights};
}  // namespace ark::es2panda::lsp

LSPAPI const *GetImpl()
{
    return &ark::es2panda::lsp::g_lspImpl;
}
