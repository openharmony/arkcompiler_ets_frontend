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

KNativePointer impl_getClassPropertyInfo(KNativePointer context, KInt position, KBoolean shouldCollectInherited)
{
    LSPAPI const *ctx = GetImpl();
    auto info = ctx->getClassPropertyInfo(reinterpret_cast<es2panda_Context *>(context),
                                          static_cast<std::size_t>(position), shouldCollectInherited != 0);
    return new std::vector<FieldsInfo>(info);
}
TS_INTEROP_3(getClassPropertyInfo, KNativePointer, KNativePointer, KInt, KBoolean)

KNativePointer impl_getNameFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldsInfo *>(infoPtr);
    return new std::string(info->name);
}
TS_INTEROP_1(getNameFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getFieldListPropertyFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldsInfo *>(infoPtr);
    std::vector<void *> ptrs;
    for (auto &el : info->properties) {
        ptrs.push_back(new FieldListProperty(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getFieldListPropertyFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getKindFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldListProperty *>(infoPtr);
    return new std::string(info->kind);
}
TS_INTEROP_1(getKindFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getModifierKindsFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldListProperty *>(infoPtr);
    std::vector<void *> ptrs;
    for (auto &el : info->modifierKinds.value()) {
        ptrs.push_back(new std::string(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getModifierKindsFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getDisplayNameFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldListProperty *>(infoPtr);
    return new std::string(info->displayName);
}
TS_INTEROP_1(getDisplayNameFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getStartFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldListProperty *>(infoPtr);
    return new std::size_t(info->start);
}
TS_INTEROP_1(getStartFromPropertyInfo, KNativePointer, KNativePointer)

KNativePointer impl_getEndFromPropertyInfo(KNativePointer infoPtr)
{
    auto info = reinterpret_cast<FieldListProperty *>(infoPtr);
    return new std::size_t(info->end);
}
TS_INTEROP_1(getEndFromPropertyInfo, KNativePointer, KNativePointer)

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

KNativePointer impl_findSafeDeleteLocation(KNativePointer context, KNativePointer declInfo)
{
    LSPAPI const *ctx = GetImpl();
    auto *result = new std::vector<SafeDeleteLocation>(
        ctx->FindSafeDeleteLocation(reinterpret_cast<es2panda_Context *>(context),
                                    reinterpret_cast<std::tuple<std::string, std::string> *>(declInfo)));
    return result;
}
TS_INTEROP_2(findSafeDeleteLocation, KNativePointer, KNativePointer, KNativePointer)

KNativePointer impl_getSafeDeleteLocations(KNativePointer safeDeleteLocationsPtr)
{
    auto *locations = reinterpret_cast<std::vector<SafeDeleteLocation> *>(safeDeleteLocationsPtr);
    std::vector<void *> ptrs;
    for (auto &loc : *locations) {
        ptrs.push_back(new SafeDeleteLocation(loc));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSafeDeleteLocations, KNativePointer, KNativePointer)

KNativePointer impl_getSafeDeleteLocationUri(KNativePointer locationPtr)
{
    auto *location = reinterpret_cast<SafeDeleteLocation *>(locationPtr);
    return new std::string(location->uri);
}
TS_INTEROP_1(getSafeDeleteLocationUri, KNativePointer, KNativePointer)

KInt impl_getSafeDeleteLocationStart(KNativePointer locationPtr)
{
    auto *location = reinterpret_cast<SafeDeleteLocation *>(locationPtr);
    return static_cast<KInt>(location->start);
}
TS_INTEROP_1(getSafeDeleteLocationStart, KInt, KNativePointer)

KInt impl_getSafeDeleteLocationLength(KNativePointer locationPtr)
{
    auto *location = reinterpret_cast<SafeDeleteLocation *>(locationPtr);
    return static_cast<KInt>(location->length);
}
TS_INTEROP_1(getSafeDeleteLocationLength, KInt, KNativePointer)

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

KNativePointer impl_organizeImports(KNativePointer context, KStringPtr &filenamePtr)
{
    LSPAPI const *ctx = GetImpl();
    auto result = ctx->OrganizeImportsImpl(reinterpret_cast<es2panda_Context *>(context), GetStringCopy(filenamePtr));
    return new std::vector<FileTextChanges>(result);
}
TS_INTEROP_2(organizeImports, KNativePointer, KNativePointer, KStringPtr)

KNativePointer impl_getFileTextChanges(KNativePointer fileTextChangesVecPtr)
{
    auto *vec = reinterpret_cast<std::vector<FileTextChanges> *>(fileTextChangesVecPtr);
    std::vector<void *> ptrs;
    for (auto &el : *vec) {
        ptrs.push_back(new FileTextChanges(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getFileTextChanges, KNativePointer, KNativePointer)

KNativePointer impl_getFileNameFromFileTextChanges(KNativePointer fileTextChangesPtr)
{
    auto *ftc = reinterpret_cast<FileTextChanges *>(fileTextChangesPtr);
    return new std::string(ftc->fileName);
}
TS_INTEROP_1(getFileNameFromFileTextChanges, KNativePointer, KNativePointer)

KNativePointer impl_getTextChangesFromFileTextChanges(KNativePointer fileTextChangesPtr)
{
    auto *ftc = reinterpret_cast<FileTextChanges *>(fileTextChangesPtr);
    std::vector<void *> ptrs;
    for (auto &el : ftc->textChanges) {
        ptrs.push_back(new TextChange(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getTextChangesFromFileTextChanges, KNativePointer, KNativePointer)

KNativePointer impl_getTextSpanFromTextChange(KNativePointer textChangePtr)
{
    auto *tc = reinterpret_cast<TextChange *>(textChangePtr);
    return new TextSpan(tc->span);
}
TS_INTEROP_1(getTextSpanFromTextChange, KNativePointer, KNativePointer)

KNativePointer impl_getNewTextFromTextChange(KNativePointer textChangePtr)
{
    auto *tc = reinterpret_cast<TextChange *>(textChangePtr);
    return new std::string(tc->newText);
}
TS_INTEROP_1(getNewTextFromTextChange, KNativePointer, KNativePointer)

KNativePointer impl_getCompletionEntryDetails(KStringPtr &entrynamePtr, KStringPtr &filenamePtr, KNativePointer context,
                                              KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *ci = new CompletionEntryDetails(
        ctx->getCompletionEntryDetails(GetStringCopy(entrynamePtr), GetStringCopy(filenamePtr),
                                       reinterpret_cast<es2panda_Context *>(context), position));
    return ci;
}
TS_INTEROP_4(getCompletionEntryDetails, KNativePointer, KStringPtr, KStringPtr, KNativePointer, KInt)

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

KNativePointer impl_createTextSpan(KInt start, KInt length)
{
    return new TextSpan(start, length);
}
TS_INTEROP_2(createTextSpan, KNativePointer, KInt, KInt)

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

KBoolean impl_getSafeDeleteInfo(KNativePointer context, KInt position, KStringPtr &path)
{
    LSPAPI const *ctx = GetImpl();
    return static_cast<KBoolean>(
        ctx->getSafeDeleteInfo(reinterpret_cast<es2panda_Context *>(context), position, GetStringCopy(path)));
}
TS_INTEROP_3(getSafeDeleteInfo, KBoolean, KNativePointer, KInt, KStringPtr)

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

KNativePointer impl_getTypeHierarchies(KNativePointer searchContext, KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *info = new TypeHierarchiesInfo(ctx->getTypeHierarchies(reinterpret_cast<es2panda_Context *>(searchContext),
                                                                 reinterpret_cast<es2panda_Context *>(context),
                                                                 static_cast<std::size_t>(position)));
    return info;
}
TS_INTEROP_3(getTypeHierarchies, KNativePointer, KNativePointer, KNativePointer, KInt)

KNativePointer impl_getFileNameFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return new std::string(info->fileName);
}
TS_INTEROP_1(getFileNameFromTypeHierarchiesInfo, KNativePointer, KNativePointer)

KNativePointer impl_getNameFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return new std::string(info->name);
}
TS_INTEROP_1(getNameFromTypeHierarchiesInfo, KNativePointer, KNativePointer)

KInt impl_getTypeFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return static_cast<size_t>(info->type);
}
TS_INTEROP_1(getTypeFromTypeHierarchiesInfo, KInt, KNativePointer)

KInt impl_getPositionFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return static_cast<size_t>(info->pos);
}
TS_INTEROP_1(getPositionFromTypeHierarchiesInfo, KInt, KNativePointer)

KNativePointer impl_getSuperFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return new TypeHierarchies(info->superHierarchies);
}
TS_INTEROP_1(getSuperFromTypeHierarchiesInfo, KNativePointer, KNativePointer)

KNativePointer impl_getSubFromTypeHierarchiesInfo(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchiesInfo *>(infoPtr);
    return new TypeHierarchies(info->subHierarchies);
}
TS_INTEROP_1(getSubFromTypeHierarchiesInfo, KNativePointer, KNativePointer)

KNativePointer impl_getFileNameFromTypeHierarchies(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchies *>(infoPtr);
    return new std::string(info->fileName);
}
TS_INTEROP_1(getFileNameFromTypeHierarchies, KNativePointer, KNativePointer)

KNativePointer impl_getNameFromTypeHierarchies(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchies *>(infoPtr);
    return new std::string(info->name);
}
TS_INTEROP_1(getNameFromTypeHierarchies, KNativePointer, KNativePointer)

KInt impl_getPosFromTypeHierarchies(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchies *>(infoPtr);
    return static_cast<size_t>(info->pos);
}
TS_INTEROP_1(getPosFromTypeHierarchies, KInt, KNativePointer)

KNativePointer impl_getSubOrSuper(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchies *>(infoPtr);
    std::vector<void *> ptrs;
    for (auto &el : info->subOrSuper) {
        ptrs.push_back(new TypeHierarchies(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSubOrSuper, KNativePointer, KNativePointer)

KInt impl_getTypeFromTypeHierarchies(KNativePointer infoPtr)
{
    auto *info = reinterpret_cast<TypeHierarchies *>(infoPtr);
    return static_cast<size_t>(info->type);
}
TS_INTEROP_1(getTypeFromTypeHierarchies, KInt, KNativePointer)

KNativePointer impl_getSpanOfEnclosingComment(KNativePointer context, KInt position, KBoolean onlyMultiLine)
{
    LSPAPI const *ctx = GetImpl();
    auto *textSpan = new TextSpan(
        ctx->getSpanOfEnclosingComment(reinterpret_cast<es2panda_Context *>(context), position, onlyMultiLine != 0));
    return textSpan;
}
TS_INTEROP_3(getSpanOfEnclosingComment, KNativePointer, KNativePointer, KInt, KBoolean)

KNativePointer impl_getInlayHintText(KNativePointer hintPtr)
{
    auto *hint = reinterpret_cast<InlayHint *>(hintPtr);
    return &hint->text;
}
TS_INTEROP_1(getInlayHintText, KNativePointer, KNativePointer)

KInt impl_getInlayHintNumber(KNativePointer hintPtr)
{
    auto *hint = reinterpret_cast<InlayHint *>(hintPtr);
    return hint->number;
}
TS_INTEROP_1(getInlayHintNumber, KInt, KNativePointer)

KInt impl_getInlayHintKind(KNativePointer hintPtr)
{
    auto *hint = reinterpret_cast<InlayHint *>(hintPtr);
    return static_cast<size_t>(hint->kind);
}
TS_INTEROP_1(getInlayHintKind, KInt, KNativePointer)

KBoolean impl_getInlayHintWhitespaceBefore(KNativePointer hintPtr)
{
    auto *hint = reinterpret_cast<InlayHint *>(hintPtr);
    return hint->whitespaceBefore ? 1 : 0;
}
TS_INTEROP_1(getInlayHintWhitespaceBefore, KBoolean, KNativePointer)

KBoolean impl_getInlayHintWhitespaceAfter(KNativePointer hintPtr)
{
    auto *hint = reinterpret_cast<InlayHint *>(hintPtr);
    return hint->whitespaceAfter ? 1 : 0;
}
TS_INTEROP_1(getInlayHintWhitespaceAfter, KBoolean, KNativePointer)

KNativePointer impl_getInlayHints(KNativePointer inlayHintListPtr)
{
    auto *inlayHintList = reinterpret_cast<InlayHintList *>(inlayHintListPtr);
    std::vector<void *> ptrs;
    for (auto &el : inlayHintList->hints) {
        ptrs.push_back(new InlayHint(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getInlayHints, KNativePointer, KNativePointer)

KNativePointer impl_getInlayHintList(KNativePointer context, KNativePointer span)
{
    LSPAPI const *ctx = GetImpl();
    auto *inlayHints = new InlayHintList(
        ctx->provideInlayHints(reinterpret_cast<es2panda_Context *>(context), reinterpret_cast<TextSpan *>(span)));
    return inlayHints;
}
TS_INTEROP_2(getInlayHintList, KNativePointer, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpParameterName(KNativePointer parameterPtr)
{
    auto *parameterRef = reinterpret_cast<SignatureHelpParameter *>(parameterPtr);
    return &parameterRef->GetName();
}
TS_INTEROP_1(getSignatureHelpParameterName, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpParameterDocumentation(KNativePointer parameterPtr)
{
    auto *parameterRef = reinterpret_cast<SignatureHelpParameter *>(parameterPtr);
    std::vector<void *> ptrs;
    for (auto &el : parameterRef->GetDocumentation()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpParameterDocumentation, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpParameterDisplayParts(KNativePointer parameterPtr)
{
    auto *parameterRef = reinterpret_cast<SignatureHelpParameter *>(parameterPtr);
    std::vector<void *> ptrs;
    for (auto &el : parameterRef->GetDisplayParts()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpParameterDisplayParts, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItemPrefix(KNativePointer itemPtr)
{
    auto *itemRef = reinterpret_cast<SignatureHelpItem *>(itemPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemRef->GetPrefixDisplayParts()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItemPrefix, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItemSuffix(KNativePointer itemPtr)
{
    auto *itemRef = reinterpret_cast<SignatureHelpItem *>(itemPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemRef->GetSuffixDisplayParts()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItemSuffix, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItemSeparator(KNativePointer itemPtr)
{
    auto *itemRef = reinterpret_cast<SignatureHelpItem *>(itemPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemRef->GetSeparatorDisplayParts()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItemSeparator, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItemParameter(KNativePointer itemPtr)
{
    auto *itemRef = reinterpret_cast<SignatureHelpItem *>(itemPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemRef->GetParameters()) {
        ptrs.push_back(new SignatureHelpParameter(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItemParameter, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItemDocumentation(KNativePointer itemPtr)
{
    auto *itemRef = reinterpret_cast<SignatureHelpItem *>(itemPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemRef->GetDocumentation()) {
        ptrs.push_back(new SymbolDisplayPart(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItemDocumentation, KNativePointer, KNativePointer)

KNativePointer impl_getSignatureHelpItem(KNativePointer itemsPtr)
{
    auto *itemsRef = reinterpret_cast<SignatureHelpItems *>(itemsPtr);
    std::vector<void *> ptrs;
    for (auto &el : itemsRef->GetItems()) {
        ptrs.push_back(new SignatureHelpItem(el));
    }
    return new std::vector<void *>(ptrs);
}
TS_INTEROP_1(getSignatureHelpItem, KNativePointer, KNativePointer)

KNativePointer impl_getApplicableSpan(KNativePointer itemsPtr)
{
    auto *itemsRef = reinterpret_cast<SignatureHelpItems *>(itemsPtr);
    return new TextSpan(itemsRef->GetApplicableSpan());
}
TS_INTEROP_1(getApplicableSpan, KNativePointer, KNativePointer)

KInt impl_getSelectedItemIndex(KNativePointer itemsPtr)
{
    auto *itemsRef = reinterpret_cast<SignatureHelpItems *>(itemsPtr);
    return itemsRef->GetSelectedItemIndex();
}
TS_INTEROP_1(getSelectedItemIndex, KInt, KNativePointer)

KInt impl_getArgumentIndex(KNativePointer itemsPtr)
{
    auto *itemsRef = reinterpret_cast<SignatureHelpItems *>(itemsPtr);
    return itemsRef->GetArgumentIndex();
}
TS_INTEROP_1(getArgumentIndex, KInt, KNativePointer)

KInt impl_getArgumentCount(KNativePointer itemsPtr)
{
    auto *itemsRef = reinterpret_cast<SignatureHelpItems *>(itemsPtr);
    return itemsRef->GetArgumentCount();
}
TS_INTEROP_1(getArgumentCount, KInt, KNativePointer)

KNativePointer impl_getSignatureHelpItems(KNativePointer context, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *textSpan =
        new SignatureHelpItems(ctx->getSignatureHelpItems(reinterpret_cast<es2panda_Context *>(context), position));
    return textSpan;
}
TS_INTEROP_2(getSignatureHelpItems, KNativePointer, KNativePointer, KInt)