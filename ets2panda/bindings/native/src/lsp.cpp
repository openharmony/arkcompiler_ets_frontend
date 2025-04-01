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
#include <cstdint>
#include <string>
#include <variant>

KNativePointer impl_getCurrentTokenValue(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    return new std::string(ctx->getCurrentTokenValue(GetStringCopy(filenamePtr), static_cast<std::size_t>(position)));
}
TS_INTEROP_2(getCurrentTokenValue, KNativePointer, KStringPtr, KInt)

// diagnostics related
KNativePointer impl_getSemanticDiagnostics(KStringPtr &filenamePtr)
{
    LSPAPI const *ctx = GetImpl();
    auto *ptrDiag = new DiagnosticReferences(ctx->getSemanticDiagnostics(GetStringCopy(filenamePtr)));
    return ptrDiag;
}
TS_INTEROP_1(getSemanticDiagnostics, KNativePointer, KStringPtr)

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

KUInt impl_getPosLine(KNativePointer posPtr)
{
    auto *pos = reinterpret_cast<Position *>(posPtr);
    return pos->line_;
}
TS_INTEROP_1(getPosLine, KUInt, KNativePointer)

KUInt impl_getPosChar(KNativePointer posPtr)
{
    auto *pos = reinterpret_cast<Position *>(posPtr);
    return pos->character_;
}
TS_INTEROP_1(getPosChar, KUInt, KNativePointer)

KUInt impl_getDiagSeverity(KNativePointer diagRefPtr)
{
    auto *diagRef = reinterpret_cast<Diagnostic *>(diagRefPtr);
    return static_cast<uint32_t>(diagRef->severity_);
}
TS_INTEROP_1(getDiagSeverity, KUInt, KNativePointer)

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
        auto castedEl = static_cast<uint32_t>(el);
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

KNativePointer impl_getFileReferences(KStringPtr &filenamePtr)
{
    LSPAPI const *ctx = GetImpl();
    auto *ref = new References(ctx->getFileReferences(GetStringCopy(filenamePtr)));
    return ref;
}
TS_INTEROP_1(getFileReferences, KNativePointer, KStringPtr)

KNativePointer impl_getReferencesAtPosition(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *ref = new References(ctx->getReferencesAtPosition(GetStringCopy(filenamePtr), position));
    return ref;
}
TS_INTEROP_2(getReferencesAtPosition, KNativePointer, KStringPtr, KInt)

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

KNativePointer impl_getQuickInfoAtPosition(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *qi = new QuickInfo(ctx->getQuickInfoAtPosition(GetStringCopy(filenamePtr), position));
    return qi;
}
TS_INTEROP_2(getQuickInfoAtPosition, KNativePointer, KStringPtr, KInt)

KNativePointer impl_getCompletionAtPosition(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *ci =
        new ark::es2panda::lsp::CompletionInfo(ctx->getCompletionsAtPosition(GetStringCopy(filenamePtr), position));
    return ci;
}
TS_INTEROP_2(getCompletionAtPosition, KNativePointer, KStringPtr, KInt)

KNativePointer impl_getImplementationAtPosition(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *defInfo = new DefinitionInfo(
        ctx->getImplementationAtPosition(GetStringCopy(filenamePtr), static_cast<std::size_t>(position)));
    return defInfo;
}
TS_INTEROP_2(getImplementationAtPosition, KNativePointer, KStringPtr, KInt)

KNativePointer impl_getDefinitionAtPosition(KStringPtr &filenamePtr, KInt position)
{
    LSPAPI const *ctx = GetImpl();
    auto *defInfo = new DefinitionInfo(
        ctx->getDefinitionAtPosition(GetStringCopy(filenamePtr), static_cast<std::size_t>(position)));
    return defInfo;
}
TS_INTEROP_2(getDefinitionAtPosition, KNativePointer, KStringPtr, KInt)

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

KNativePointer impl_getDocumentHighlights(KStringPtr &fileName, KInt pos)
{
    LSPAPI const *ctx = GetImpl();
    auto *docs = new DocumentHighlightsReferences(ctx->getDocumentHighlights(GetStringCopy(fileName), pos));
    return docs;
}
TS_INTEROP_2(getDocumentHighlights, KNativePointer, KStringPtr, KInt)

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
