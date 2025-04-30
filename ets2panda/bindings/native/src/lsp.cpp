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

#include "convertors-napi.h"
#include "lsp/include/api.h"
#include "lsp/include/completions.h"
#include "common.h"
#include "panda_types.h"
#include "public/es2panda_lib.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>

char *GetStringCopy(KStringPtr &ptr)
{
    return strdup(ptr.c_str());
}

KNativePointer impl_getCurrentTokenValue(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    return new std::string(
        ctx->getCurrentTokenValue(reinterpret_cast<es2panda_Context *>(context), static_cast<std::size_t>(position)));
}
TS_INTEROP_2(getCurrentTokenValue, KNativePointer, KNativePointer, KInt)

// diagnostics related
KNativePointer impl_getSemanticDiagnostics(KNativePointer context)
{
    LSPAPI const *ctx = GetImpl();
    auto *ptrDiag =
        new DiagnosticReferences(ctx->getSemanticDiagnostics(reinterpret_cast<es2panda_Context *>(context)));
    return ptrDiag;
}
TS_INTEROP_1(getSemanticDiagnostics, KNativePointer, KNativePointer)

KNativePointer impl_getSyntacticDiagnostics(KNativePointer context)
{
    LSPAPI const *ctx = GetImpl();
    auto *ptrDiag =
        new DiagnosticReferences(ctx->getSyntacticDiagnostics(reinterpret_cast<es2panda_Context *>(context)));
    return ptrDiag;
}
TS_INTEROP_1(getSyntacticDiagnostics, KNativePointer, KNativePointer)

KNativePointer impl_getDiags(KNativePointer diagRefsPtr)
{
    auto *diagRefs = reinterpret_cast<DiagnosticReferences *>(diagRefsPtr);
    std::vector<void *> ptrs;
    for (auto &el : diagRefs->diagnostic) {
        ptrs.push_back(new Diagnostic(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getDiags, KNativePointer, KNativePointer)

KNativePointer impl_getDiagMsg(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return new std::string(diagRef->message_);
}
TS_INTEROP_1(getDiagMsg, KNativePointer, KNativePointer)

KNativePointer impl_getDiagRange(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return &diagRef->range_;
}
TS_INTEROP_1(getDiagRange, KNativePointer, KNativePointer)

KNativePointer impl_getRangeEnd(KNativePointer rangePtr)
{
    auto *range = reinterpret_cast<Range *>(rangePtr);
    return &range->end;
}
TS_INTEROP_1(getRangeEnd, KNativePointer, KNativePointer)

KNativePointer impl_getRangeStart(KNativePointer rangePtr)
{
    auto *range = reinterpret_cast<Range *>(rangePtr);
    return &range->start;
}
TS_INTEROP_1(getRangeStart, KNativePointer, KNativePointer)

KInt impl_getPosLine(KNativePointer posPtr)
{
    auto *pos = reinterpret_cast<Position *>(posPtr);
    return pos->line_;
}
TS_INTEROP_1(getPosLine, KInt, KNativePointer)

KInt impl_getPosChar(KNativePointer posPtr)
{
    auto *pos = reinterpret_cast<Position *>(posPtr);
    return pos->character_;
}
TS_INTEROP_1(getPosChar, KInt, KNativePointer)

KInt impl_getDiagSeverity(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return static_cast<size_t>(diagRef->severity_);
}
TS_INTEROP_1(getDiagSeverity, KInt, KNativePointer)

KNativePointer impl_getDiagCode(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return &diagRef->code_;
}
TS_INTEROP_1(getDiagCode, KNativePointer, KNativePointer)

KNativePointer impl_getDiagCodeDescription(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return &diagRef->codeDescription_;
}
TS_INTEROP_1(getDiagCodeDescription, KNativePointer, KNativePointer)

KNativePointer impl_getCodeDescriptionHref(KNativePointer codeDescrRefPtr)
{
    auto *codeDescrRef = reinterpret_cast<CodeDescription *>(codeDescrRefPtr);
    return new std::string(codeDescrRef->href_);
}
TS_INTEROP_1(getCodeDescriptionHref, KNativePointer, KNativePointer)

KNativePointer impl_getDiagTags(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    std::vector<void *> ptrs;
    for (auto el : diagRef->tags_) {
        auto castedEl = static_cast<size_t>(el);
        ptrs.push_back(&castedEl);
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getDiagTags, KNativePointer, KNativePointer)

KNativePointer impl_getDiagData(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return &diagRef->data_;
}
TS_INTEROP_1(getDiagData, KNativePointer, KNativePointer)

KNativePointer impl_getDiagRelatedInfo(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    std::vector<void *> ptrs;
    for (auto el : diagRef->relatedInformation_) {
        ptrs.push_back(&el);
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getDiagRelatedInfo, KNativePointer, KNativePointer)

KNativePointer impl_getRelatedInfoMsg(KNativePointer relatedInfoPtr)
{
    auto *relatedInfoRef = reinterpret_cast<DiagnosticRelatedInformation *>(relatedInfoPtr);
    return &relatedInfoRef->message_;
}
TS_INTEROP_1(getRelatedInfoMsg, KNativePointer, KNativePointer)

KNativePointer impl_getRelatedInfoLoc(KNativePointer relatedInfoPtr)
{
    auto *relatedInfoRef = reinterpret_cast<DiagnosticRelatedInformation *>(relatedInfoPtr);
    return &relatedInfoRef->location_;
}
TS_INTEROP_1(getRelatedInfoLoc, KNativePointer, KNativePointer)

KNativePointer impl_getLocUri(KNativePointer locPtr)
{
    auto *locRef = reinterpret_cast<Location *>(locPtr);
    return &locRef->uri_;
}
TS_INTEROP_1(getLocUri, KNativePointer, KNativePointer)

KNativePointer impl_getLocRange(KNativePointer locPtr)
{
    auto *locRef = reinterpret_cast<Location *>(locPtr);
    return &locRef->range_;
}
TS_INTEROP_1(getLocRange, KNativePointer, KNativePointer)

KNativePointer impl_getDiagSource(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return new std::string(diagRef->source_);
}
TS_INTEROP_1(getDiagSource, KNativePointer, KNativePointer)

KBoolean impl_isPackageModule(KNativePointer context)
{
    LSPAPI const *ctx = GetImpl();
    return static_cast<KBoolean>(ctx->isPackageModule(reinterpret_cast<es2panda_Context *>(context)));
}
TS_INTEROP_1(isPackageModule, KBoolean, KNativePointer)

KNativePointer impl_getFileReferences(KStringPtr &filenamePtr, KNativePointer context, KBoolean isPackageModule)
{
    LSPAPI const *ctx = GetImpl();
    auto *ref = new References(ctx->getFileReferences(
        GetStringCopy(filenamePtr), reinterpret_cast<es2panda_Context *>(context), isPackageModule != 0));
    return ref;
}
TS_INTEROP_3(getFileReferences, KNativePointer, KStringPtr, KNativePointer, KBoolean)

KNativePointer impl_getDeclInfo(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *declInfo = new DeclInfo(
        ctx->getDeclInfo(reinterpret_cast<es2panda_Context *>(context), static_cast<std::size_t>(position)));
    return declInfo;
}
TS_INTEROP_2(getDeclInfo, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getReferencesAtPosition(KNativePointer context, KNativePointer declInfo)
{
    LSPAPI const *ctx = GetImpl();
    auto *ref = new References(ctx->getReferencesAtPosition(reinterpret_cast<es2panda_Context *>(context),
                                                            reinterpret_cast<DeclInfo *>(declInfo)));
    return ref;
}
TS_INTEROP_2(getReferencesAtPosition, KNativePointer, KNativePointer, KNativePointer)

KNativePointer impl_getReferenceInfos(KNativePointer refs)
{
    auto *refsPtr = reinterpret_cast<References *>(refs);
    std::vector<void *> ptrs;
    for (auto &el : refsPtr->referenceInfos) {
        ptrs.push_back(new ReferenceInfo(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getReferenceInfos, KNativePointer, KNativePointer)

KInt impl_getReferenceStart(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<ReferenceInfo *>(ref);
    return refPtr->start;
}
TS_INTEROP_1(getReferenceStart, KInt, KNativePointer)

KInt impl_getReferenceLength(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<ReferenceInfo *>(ref);
    return refPtr->length;
}
TS_INTEROP_1(getReferenceLength, KInt, KNativePointer)

KNativePointer impl_getReferenceFileName(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<ReferenceInfo *>(ref);
    return new std::string(refPtr->fileName);
}
TS_INTEROP_1(getReferenceFileName, KNativePointer, KNativePointer)

KNativePointer impl_getDeclInfoFileName(KNativePointer declInfo)
{
    auto *declInfoPtr = reinterpret_cast<DeclInfo *>(declInfo);
    return new std::string(declInfoPtr->fileName);
}
TS_INTEROP_1(getDeclInfoFileName, KNativePointer, KNativePointer)

KNativePointer impl_getDeclInfoFileText(KNativePointer declInfo)
{
    auto *declInfoPtr = reinterpret_cast<DeclInfo *>(declInfo);
    return new std::string(declInfoPtr->fileText);
}
TS_INTEROP_1(getDeclInfoFileText, KNativePointer, KNativePointer)

KNativePointer impl_getQuickInfoAtPosition(KStringPtr &filenamePtr, KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *qi = new QuickInfo(ctx->getQuickInfoAtPosition(GetStringCopy(filenamePtr),
                                                         reinterpret_cast<es2panda_Context *>(context), position));
    return qi;
}
TS_INTEROP_3(getQuickInfoAtPosition, KNativePointer, KStringPtr, KNativePointer, KInt)

KNativePointer impl_getCompletionAtPosition(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *ci = new ark::es2panda::lsp::CompletionInfo(
        ctx->getCompletionsAtPosition(reinterpret_cast<es2panda_Context *>(context), position));
    return ci;
}
TS_INTEROP_2(getCompletionAtPosition, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getImplementationAtPosition(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *defInfo = new DefinitionInfo(ctx->getImplementationAtPosition(reinterpret_cast<es2panda_Context *>(context),
                                                                        static_cast<std::size_t>(position)));
    return defInfo;
}
TS_INTEROP_2(getImplementationAtPosition, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getDefinitionAtPosition(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *defInfo = new DefinitionInfo(ctx->getDefinitionAtPosition(reinterpret_cast<es2panda_Context *>(context),
                                                                    static_cast<std::size_t>(position)));
    return defInfo;
}
TS_INTEROP_2(getDefinitionAtPosition, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getFileNameFromDef(KNativePointer defPtr)
{
    auto *defInfo = reinterpret_cast<DefinitionInfo *>(defPtr);
    return new std::string(defInfo->fileName);
}
TS_INTEROP_1(getFileNameFromDef, KNativePointer, KNativePointer)

KInt impl_getStartFromDef(KNativePointer defPtr)
{
    auto *defInfo = reinterpret_cast<DefinitionInfo *>(defPtr);
    return defInfo->start;
}
TS_INTEROP_1(getStartFromDef, KInt, KNativePointer)

KInt impl_getLengthFromDef(KNativePointer defPtr)
{
    auto *defInfo = reinterpret_cast<DefinitionInfo *>(defPtr);
    return defInfo->length;
}
TS_INTEROP_1(getLengthFromDef, KInt, KNativePointer)

KNativePointer impl_getDocumentHighlights(KNativePointer context, KInt pos)
{
    LSPAPI const *ctx = GetImpl();
    auto *docs = new DocumentHighlightsReferences(
        ctx->getDocumentHighlights(reinterpret_cast<es2panda_Context *>(context), pos));
    return docs;
}
TS_INTEROP_2(getDocumentHighlights, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getDocumentHighs(KNativePointer doc)
{
    auto *dhr = reinterpret_cast<DocumentHighlightsReferences *>(doc);
    std::vector<void *> ptrs;
    for (auto &el : dhr->documentHighlights_) {
        ptrs.push_back(new DocumentHighlights(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getDocumentHighs, KNativePointer, KNativePointer)

KNativePointer impl_getSuggestionDiagnostics(KNativePointer context)
{
    LSPAPI const *ctx = GetImpl();
    auto *ptrDiag =
        new DiagnosticReferences(ctx->getSuggestionDiagnostics(reinterpret_cast<es2panda_Context *>(context)));
    return ptrDiag;
}
TS_INTEROP_1(getSuggestionDiagnostics, KNativePointer, KNativePointer)

KNativePointer impl_getDisplayPartsText(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<SymbolDisplayPart *>(ref);
    return new std::string(refPtr->GetText());
}
TS_INTEROP_1(getDisplayPartsText, KNativePointer, KNativePointer)

KNativePointer impl_getDisplayPartsKind(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<SymbolDisplayPart *>(ref);
    return new std::string(refPtr->GetKind());
}
TS_INTEROP_1(getDisplayPartsKind, KNativePointer, KNativePointer)

KNativePointer impl_getQuickInfoKind(KNativePointer quickInfoPtr)
{
    auto *quickInfo = reinterpret_cast<QuickInfo *>(quickInfoPtr);
    return new std::string(quickInfo->GetKind());
}
TS_INTEROP_1(getQuickInfoKind, KNativePointer, KNativePointer)

KNativePointer impl_getQuickInfoKindModifier(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<QuickInfo *>(ref);
    return new std::string(refPtr->GetKindModifiers());
}
TS_INTEROP_1(getQuickInfoKindModifier, KNativePointer, KNativePointer)

KNativePointer impl_getQuickInfoFileName(KNativePointer ref)
{
    auto *refPtr = reinterpret_cast<QuickInfo *>(ref);
    return new std::string(refPtr->GetFileName());
}
TS_INTEROP_1(getQuickInfoFileName, KNativePointer, KNativePointer)

KNativePointer impl_getSymbolDisplayPart(KNativePointer quickInfoPtr)
{
    auto *quickInfo = reinterpret_cast<QuickInfo *>(quickInfoPtr);
    std::vector<void *> ptrs;
    for (auto &el : quickInfo->GetDisplayParts()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSymbolDisplayPart, KNativePointer, KNativePointer)

KInt impl_getTextSpanStart(KNativePointer textSpanPtr)
{
    auto *textSpan = reinterpret_cast<TextSpan *>(textSpanPtr);
    return textSpan->start;
}
TS_INTEROP_1(getTextSpanStart, KInt, KNativePointer)

KInt impl_getTextSpanLength(KNativePointer textSpanPtr)
{
    auto *textSpan = reinterpret_cast<TextSpan *>(textSpanPtr);
    return textSpan->length;
}
TS_INTEROP_1(getTextSpanLength, KInt, KNativePointer)

KNativePointer impl_getTextSpan(KNativePointer quickInfoPtr)
{
    auto *quickInfo = reinterpret_cast<QuickInfo *>(quickInfoPtr);
    return new TextSpan(quickInfo->GetTextSpan());
}
TS_INTEROP_1(getTextSpan, KNativePointer, KNativePointer)

KNativePointer impl_getHighlightTextSpan(KNativePointer highlightPtr)
{
    auto *highlight = reinterpret_cast<HighlightSpan *>(highlightPtr);
    return new TextSpan(highlight->textSpan_);
}
TS_INTEROP_1(getHighlightTextSpan, KNativePointer, KNativePointer)

KNativePointer impl_getHighlightContextSpan(KNativePointer highlightPtr)
{
    auto *highlight = reinterpret_cast<HighlightSpan *>(highlightPtr);
    return new TextSpan(highlight->contextSpan_);
}
TS_INTEROP_1(getHighlightContextSpan, KNativePointer, KNativePointer)

KNativePointer impl_getHighlightFileName(KNativePointer highlightPtr)
{
    auto *highlight = reinterpret_cast<HighlightSpan *>(highlightPtr);
    return new std::string(highlight->fileName_);
}
TS_INTEROP_1(getHighlightFileName, KNativePointer, KNativePointer)

KInt impl_getHighlightIsInString(KNativePointer highlightPtr)
{
    auto *highlight = reinterpret_cast<HighlightSpan *>(highlightPtr);
    return static_cast<int>(highlight->isInString_);
}
TS_INTEROP_1(getHighlightIsInString, KInt, KNativePointer)

KInt impl_getHighlightKind(KNativePointer highlightPtr)
{
    auto *highlight = reinterpret_cast<HighlightSpan *>(highlightPtr);
    return static_cast<size_t>(highlight->kind_);
}
TS_INTEROP_1(getHighlightKind, KInt, KNativePointer)

KNativePointer impl_getHighlightSpanFromHighlights(KNativePointer documentHighlightsPtr)
{
    auto *documentHighlights = reinterpret_cast<DocumentHighlights *>(documentHighlightsPtr);
    std::vector<void *> ptrs;
    for (auto &el : documentHighlights->highlightSpans_) {
        ptrs.push_back(new HighlightSpan(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getHighlightSpanFromHighlights, KNativePointer, KNativePointer)

KNativePointer impl_getDocumentHighlightsFromRef(KNativePointer documentHighlightsReferencesPtr)
{
    auto *documentHighlightsReferences =
        reinterpret_cast<DocumentHighlightsReferences *>(documentHighlightsReferencesPtr);
    std::vector<void *> ptrs;
    for (auto &el : documentHighlightsReferences->documentHighlights_) {
        ptrs.push_back(new DocumentHighlights(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getDocumentHighlightsFromRef, KNativePointer, KNativePointer)

KNativePointer impl_getFileNameFromEntryData(KNativePointer entryDataPtr)
{
    auto *entryData = reinterpret_cast<ark::es2panda::lsp::CompletionEntryData *>(entryDataPtr);
    return new std::string(entryData->GetFileName());
}
TS_INTEROP_1(getFileNameFromEntryData, KNativePointer, KNativePointer)

KNativePointer impl_getNamedExportFromEntryData(KNativePointer entryDataPtr)
{
    auto *entryData = reinterpret_cast<ark::es2panda::lsp::CompletionEntryData *>(entryDataPtr);
    return new std::string(entryData->GetNamedExport());
}
TS_INTEROP_1(getNamedExportFromEntryData, KNativePointer, KNativePointer)

KNativePointer impl_getImportDeclarationFromEntryData(KNativePointer entryDataPtr)
{
    auto *entryData = reinterpret_cast<ark::es2panda::lsp::CompletionEntryData *>(entryDataPtr);
    return new std::string(entryData->GetImportDeclaration());
}
TS_INTEROP_1(getImportDeclarationFromEntryData, KNativePointer, KNativePointer)

KInt impl_getStatusFromEntryData(KNativePointer entryDataPtr)
{
    auto *entryData = reinterpret_cast<ark::es2panda::lsp::CompletionEntryData *>(entryDataPtr);
    return static_cast<size_t>(entryData->GetStatus());
}
TS_INTEROP_1(getStatusFromEntryData, KInt, KNativePointer)

KNativePointer impl_getNameFromEntry(KNativePointer entryPtr)
{
    auto *entry = reinterpret_cast<ark::es2panda::lsp::CompletionEntry *>(entryPtr);
    return new std::string(entry->GetName());
}
TS_INTEROP_1(getNameFromEntry, KNativePointer, KNativePointer)

KNativePointer impl_getSortTextFromEntry(KNativePointer entryPtr)
{
    auto *entry = reinterpret_cast<ark::es2panda::lsp::CompletionEntry *>(entryPtr);
    return new std::string(entry->GetSortText());
}
TS_INTEROP_1(getSortTextFromEntry, KNativePointer, KNativePointer)

KNativePointer impl_getInsertTextFromEntry(KNativePointer entryPtr)
{
    auto *entry = reinterpret_cast<ark::es2panda::lsp::CompletionEntry *>(entryPtr);
    return new std::string(entry->GetInsertText());
}
TS_INTEROP_1(getInsertTextFromEntry, KNativePointer, KNativePointer)

KInt impl_getKindFromEntry(KNativePointer entryPtr)
{
    auto *entry = reinterpret_cast<ark::es2panda::lsp::CompletionEntry *>(entryPtr);
    return static_cast<size_t>(entry->GetCompletionKind());
}
TS_INTEROP_1(getKindFromEntry, KInt, KNativePointer)

KNativePointer impl_getDataFromEntry(KNativePointer entryPtr)
{
    auto *entry = reinterpret_cast<ark::es2panda::lsp::CompletionEntry *>(entryPtr);
    auto data = entry->GetCompletionEntryData();

    if (data.has_value()) {
        return new ark::es2panda::lsp::CompletionEntryData(data.value());
    }
    return nullptr;
}
TS_INTEROP_1(getDataFromEntry, KNativePointer, KNativePointer)

KNativePointer impl_getEntriesFromCompletionInfo(KNativePointer completionInfoPtr)
{
    auto *completionInfo = reinterpret_cast<ark::es2panda::lsp::CompletionInfo *>(completionInfoPtr);
    std::vector<void *> ptrs;
    for (auto &el : completionInfo->GetEntries()) {
        ptrs.push_back(new ark::es2panda::lsp::CompletionEntry(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getEntriesFromCompletionInfo, KNativePointer, KNativePointer)

KNativePointer impl_getUriFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return new std::string(loc->uri);
}
TS_INTEROP_1(getUriFromLocation, KNativePointer, KNativePointer)

KInt impl_getStartFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return loc->start;
}
TS_INTEROP_1(getStartFromLocation, KInt, KNativePointer)

KInt impl_getEndFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return loc->end;
}
TS_INTEROP_1(getEndFromLocation, KInt, KNativePointer)

KBoolean impl_getIsDefinitionFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return static_cast<KBoolean>(loc->isDefinition);
}
TS_INTEROP_1(getIsDefinitionFromLocation, KBoolean, KNativePointer)

KBoolean impl_getIsImportFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return static_cast<KBoolean>(loc->isImport);
}
TS_INTEROP_1(getIsImportFromLocation, KBoolean, KNativePointer)

KInt impl_getAccessKindFromLocation(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ReferenceLocation *>(locPtr);
    return static_cast<size_t>(loc->accessKind);
}
TS_INTEROP_1(getAccessKindFromLocation, KInt, KNativePointer)

KNativePointer impl_getLocationFromList(KNativePointer listPtr)
{
    auto *list = reinterpret_cast<ReferenceLocationList *>(listPtr);
    std::vector<void *> ptrs;
    for (auto &el : list->referenceLocation) {
        ptrs.push_back(new ReferenceLocation(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getLocationFromList, KNativePointer, KNativePointer)

KNativePointer impl_toLineColumnOffset(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *ptrDiag = new ark::es2panda::lsp::LineAndCharacter(
        ctx->toLineColumnOffset(reinterpret_cast<es2panda_Context *>(context), position));
    return ptrDiag;
}
TS_INTEROP_2(toLineColumnOffset, KNativePointer, KNativePointer, KInt)

KInt impl_getLine(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ark::es2panda::lsp::LineAndCharacter *>(locPtr);
    return loc->GetLine();
}
TS_INTEROP_1(getLine, KInt, KNativePointer)

KInt impl_getChar(KNativePointer locPtr)
{
    auto *loc = reinterpret_cast<ark::es2panda::lsp::LineAndCharacter *>(locPtr);
    return loc->GetCharacter();
}
TS_INTEROP_1(getChar, KInt, KNativePointer)