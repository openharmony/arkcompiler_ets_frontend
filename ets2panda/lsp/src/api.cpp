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

#include "api.h"
#include <cstddef>
#include <string>
#include <vector>
#include "compiler/lowering/util.h"
#include "internal_api.h"
#include "ir/astNode.h"
#include "references.h"
#include "public/es2panda_lib.h"
#include "cancellation_token.h"
#include "public/public.h"
#include "util/options.h"
#include "quick_info.h"
#include "suggestion_diagnostics.h"
#include "brace_matching.h"
#include "line_column_offset.h"
#include "services/services.h"

extern "C" {
namespace ark::es2panda::lsp {

DefinitionInfo GetDefinitionAtPosition(es2panda_Context *context, size_t position)
{
    auto declInfo = GetDefinitionAtPositionImpl(context, position);
    DefinitionInfo result {};
    auto node = declInfo.first;
    while (node != nullptr) {
        if (node->IsETSModule()) {
            auto name = std::string(node->AsETSModule()->Program()->SourceFilePath());
            auto targetNode = declInfo.first->FindChild([&declInfo](ir::AstNode *childNode) {
                return childNode->IsIdentifier() && childNode->AsIdentifier()->Name() == declInfo.second;
            });
            if (targetNode != nullptr) {
                result = {name, targetNode->Start().index, targetNode->End().index - targetNode->Start().index};
            }
            break;
        }
        node = node->Parent();
    }
    return result;
}

DefinitionInfo GetImplementationAtPosition(es2panda_Context *context, size_t position)
{
    return GetDefinitionAtPosition(context, position);
}

bool IsPackageModule(es2panda_Context *context)
{
    return reinterpret_cast<public_lib::Context *>(context)->parserProgram->IsPackage();
}

References GetFileReferences(char const *fileName, es2panda_Context *context, bool isPackageModule)
{
    return GetFileReferencesImpl(context, fileName, isPackageModule);
}

DeclInfo GetDeclInfo(es2panda_Context *context, size_t position)
{
    DeclInfo result;
    if (context == nullptr) {
        return result;
    }
    auto astNode = GetTouchingToken(context, position, false);
    auto declInfo = GetDeclInfoImpl(astNode);
    result.fileName = std::get<0>(declInfo);
    result.fileText = std::get<1>(declInfo);
    return result;
}

References GetReferencesAtPosition(es2panda_Context *context, DeclInfo *declInfo)
{
    auto result = GetReferencesAtPositionImpl(context, {declInfo->fileName, declInfo->fileText});
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

es2panda_AstNode *GetPrecedingToken(es2panda_Context *context, const size_t pos)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = ctx->parserProgram->Ast();
    return reinterpret_cast<es2panda_AstNode *>(FindPrecedingToken(pos, ast, ctx->allocator));
}

std::string GetCurrentTokenValue(es2panda_Context *context, size_t position)
{
    auto result = GetCurrentTokenValueImpl(context, position);
    return result;
}

QuickInfo GetQuickInfoAtPosition(const char *fileName, es2panda_Context *context, size_t position)
{
    auto res = GetQuickInfoAtPositionImpl(context, position, fileName);
    return res;
}

TextSpan GetSpanOfEnclosingComment(char const *fileName, size_t pos, bool onlyMultiLine)
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

DiagnosticReferences GetSemanticDiagnostics(es2panda_Context *context)
{
    DiagnosticReferences result {};
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    const auto &diagnostics = ctx->diagnosticEngine->GetDiagnosticStorage(util::DiagnosticType::SEMANTIC);
    for (const auto &diagnostic : diagnostics) {
        result.diagnostic.push_back(CreateDiagnosticForError(context, *diagnostic));
    }
    return result;
}

DiagnosticReferences GetSyntacticDiagnostics(es2panda_Context *context)
{
    DiagnosticReferences result {};
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    const auto &diagnostics = ctx->diagnosticEngine->GetDiagnosticStorage(util::DiagnosticType::SYNTAX);
    for (const auto &diagnostic : diagnostics) {
        result.diagnostic.push_back(CreateDiagnosticForError(context, *diagnostic));
    }
    return result;
}

DiagnosticReferences GetCompilerOptionsDiagnostics(char const *fileName, CancellationToken cancellationToken)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);

    DiagnosticReferences result {};
    if (cancellationToken.IsCancellationRequested()) {
        return result;
    }
    GetOptionDiagnostics(context, result);

    auto options = reinterpret_cast<public_lib::Context *>(context)->config->options;
    auto compilationList = FindProjectSources(options->ArkTSConfig());
    initializer.DestroyContext(context);

    for (auto const &file : compilationList) {
        if (cancellationToken.IsCancellationRequested()) {
            return result;
        }
        auto fileContext = initializer.CreateContext(file.first.c_str(), ES2PANDA_STATE_CHECKED);
        GetGlobalDiagnostics(fileContext, result);
        initializer.DestroyContext(fileContext);
    }

    return result;
}

DocumentHighlightsReferences GetDocumentHighlights(es2panda_Context *context, size_t position)
{
    DocumentHighlightsReferences result = {};
    result.documentHighlights_.push_back(GetDocumentHighlightsImpl(context, position));
    return result;
}

std::vector<ark::es2panda::lsp::ReferencedNode> FindReferencesWrapper(
    ark::es2panda::lsp::CancellationToken *tkn, const std::vector<ark::es2panda::SourceFile> &srcFiles,
    const ark::es2panda::SourceFile &srcFile, size_t position)
{
    auto tmp = FindReferences(tkn, srcFiles, srcFile, position);
    std::vector<ark::es2panda::lsp::ReferencedNode> res(tmp.size());
    for (const auto &entry : tmp) {
        res.emplace_back(entry);
    }
    return res;
}

std::vector<TextSpan> GetBraceMatchingAtPositionWrapper(char const *fileName, size_t position)
{
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext(fileName, ES2PANDA_STATE_CHECKED);
    auto result = GetBraceMatchingAtPosition(context, position);
    initializer.DestroyContext(context);
    return result;
}

std::vector<ark::es2panda::lsp::RenameLocation> FindRenameLocationsWrapper(
    const std::vector<ark::es2panda::SourceFile> &srcFiles, const ark::es2panda::SourceFile &srcFile, size_t position)
{
    auto tmp = FindRenameLocations(srcFiles, srcFile, position);
    std::vector<ark::es2panda::lsp::RenameLocation> res(tmp.size());
    for (const auto &entry : tmp) {
        res.emplace_back(entry);
    }
    return res;
}

std::vector<ark::es2panda::lsp::RenameLocation> FindRenameLocationsWithCancellationWrapper(
    ark::es2panda::lsp::CancellationToken *tkn, const std::vector<ark::es2panda::SourceFile> &srcFiles,
    const ark::es2panda::SourceFile &srcFile, size_t position)
{
    auto tmp = FindRenameLocations(tkn, srcFiles, srcFile, position);
    std::vector<ark::es2panda::lsp::RenameLocation> res(tmp.size());
    for (const auto &entry : tmp) {
        res.emplace_back(entry);
    }
    return res;
}

DiagnosticReferences GetSuggestionDiagnostics(es2panda_Context *context)
{
    DiagnosticReferences res {};
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = ctx->parserProgram->Ast();
    auto vec = GetSuggestionDiagnosticsImpl(ast);
    res.diagnostic.reserve(vec.size());
    for (const auto &diag : vec) {
        res.diagnostic.push_back(diag.diagnostic);
    }
    return res;
}

ark::es2panda::lsp::CompletionInfo GetCompletionsAtPosition(es2panda_Context *context, size_t position)
{
    auto result = CompletionInfo(GetCompletionsAtPositionImpl(context, position));
    return result;
}

std::vector<Location> GetImplementationLocationAtPositionWrapper(es2panda_Context *context, int position)
{
    return GetImplementationLocationAtPosition(context, position);
}

LineAndCharacter ToLineColumnOffsetWrapper(es2panda_Context *context, size_t position)
{
    auto result = ToLineColumnOffset(context, position);
    return result;
}

LSPAPI g_lspImpl = {GetDefinitionAtPosition,
                    GetImplementationAtPosition,
                    IsPackageModule,
                    GetFileReferences,
                    GetDeclInfo,
                    GetReferencesAtPosition,
                    GetPrecedingToken,
                    GetCurrentTokenValue,
                    GetQuickInfoAtPosition,
                    GetSpanOfEnclosingComment,
                    GetSemanticDiagnostics,
                    GetSyntacticDiagnostics,
                    GetCompilerOptionsDiagnostics,
                    GetDocumentHighlights,
                    FindRenameLocationsWrapper,
                    FindRenameLocationsWithCancellationWrapper,
                    FindReferencesWrapper,
                    GetSuggestionDiagnostics,
                    GetCompletionsAtPosition,
                    GetBraceMatchingAtPositionWrapper,
                    GetImplementationLocationAtPositionWrapper,
                    ToLineColumnOffsetWrapper};
}  // namespace ark::es2panda::lsp

CAPI_EXPORT LSPAPI const *GetImpl()
{
    return &ark::es2panda::lsp::g_lspImpl;
}
}
