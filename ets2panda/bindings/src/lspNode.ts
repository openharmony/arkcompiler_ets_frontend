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

import { KBoolean, KInt, KNativePointer, KUInt } from './InteropTypes';
import { unpackString, VariantTypes } from './private';
import { throwError } from './utils';
import { isNullPtr } from './Wrapper';
import { global } from './global';
import { NativePtrDecoder } from './Platform';

export abstract class LspNode {
  readonly peer: KNativePointer;

  protected constructor(peer: KNativePointer) {
    if (isNullPtr(peer)) {
      throwError('nullptr from peer in lspnode constuctor');
    }
    this.peer = peer;
  }
}

export class LspPosition extends LspNode {
  readonly line: number;
  readonly character: number;
  constructor(peer: KNativePointer) {
    super(peer);
    this.line = global.es2panda._getPosLine(peer);
    this.character = global.es2panda._getPosChar(peer);
  }
}

export class LspRange extends LspNode {
  readonly start: LspPosition;
  readonly end: LspPosition;
  constructor(peer: KNativePointer) {
    super(peer);
    this.start = new LspPosition(global.es2panda._getRangeStart(peer));
    this.end = new LspPosition(global.es2panda._getRangeEnd(peer));
  }
}

export enum LspDiagSeverity {
  Error = 1,
  Warning = 2,
  Information = 3,
  Hint = 4
}

export enum LspDiagTag {
  Unnecessary = 1,
  Deprecated = 2
}

export class LspLocation extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.uri = unpackString(global.es2panda._getLocUri(peer));
    this.range = new LspRange(global.es2panda._getLocRange(peer));
  }
  readonly uri: string;
  readonly range: LspRange;
}

export class LspRelatedInfo extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.message = unpackString(global.es2panda._getRelatedInfoMsg(peer));
    this.location = new LspLocation(global.es2panda._getRelatedInfoLoc(peer));
  }
  readonly message: string;
  readonly location: LspLocation;
}

export class LspCodeDescription extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.href = unpackString(global.es2panda._getCodeDescriptionHref(peer));
  }
  readonly href: string;
}

export class LspDiagnosticNode extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.message = unpackString(global.es2panda._getDiagMsg(peer));
    this.source = unpackString(global.es2panda._getDiagSource(peer));
    this.range = new LspRange(global.es2panda._getDiagRange(peer));
    this.tags = new NativePtrDecoder()
      .decode(global.es2panda._getDiagTags(peer))
      .map((elPeer: KNativePointer) => elPeer as KInt);
    this.relatedInfo = new NativePtrDecoder()
      .decode(global.es2panda._getDiagRelatedInfo(peer))
      .map((elPeer: KNativePointer) => new LspRelatedInfo(elPeer));
    let codeVarPtr = global.es2panda._getDiagCode(peer);
    if (global.interop._getTypeOfVariant(codeVarPtr) === VariantTypes.VARIANT_INT) {
      this.code = global.interop._getIntFromVariant(codeVarPtr);
    } else {
      this.code = unpackString(global.interop._getStringFromVariant(codeVarPtr));
    }
    let dataPtr = global.es2panda._getDiagData(peer);
    if (global.interop._getTypeOfVariant(dataPtr) === VariantTypes.VARIANT_INT) {
      this.data = global.interop._getIntFromVariant(dataPtr);
    } else {
      this.data = unpackString(global.interop._getStringFromVariant(dataPtr));
    }
    this.severity = global.es2panda._getDiagSeverity(peer);
    this.codeDescription = new LspCodeDescription(global.es2panda._getDiagCodeDescription(peer));
  }
  readonly source: String;
  readonly message: String;
  readonly range: LspRange;
  readonly codeDescription: LspCodeDescription;
  readonly severity: LspDiagSeverity;
  readonly tags: LspDiagTag[];
  readonly relatedInfo: LspRelatedInfo[];
  readonly code: number | String;
  readonly data: number | string;
}

export class LspDiagsNode extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.diagnostics = new NativePtrDecoder()
      .decode(global.es2panda._getDiags(this.peer))
      .map((elPeer: KNativePointer) => {
        return new LspDiagnosticNode(elPeer);
      });
  }
  readonly diagnostics: LspDiagnosticNode[];
}

export class LspDefinitionData extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getFileNameFromDef(peer));
    this.start = global.es2panda._getStartFromDef(peer);
    this.length = global.es2panda._getLengthFromDef(peer);
  }
  readonly fileName: String;
  readonly start: KInt;
  readonly length: KInt;
}

export class LspReferenceData extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getReferenceFileName(peer));
    this.start = global.es2panda._getReferenceStart(peer);
    this.length = global.es2panda._getReferenceLength(peer);
  }
  readonly fileName: String;
  readonly start: KInt;
  readonly length: KInt;
}

export class LspDeclInfo extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getDeclInfoFileName(peer));
    this.fileText = unpackString(global.es2panda._getDeclInfoFileText(peer));
  }
  readonly fileName: String;
  readonly fileText: String;
}

export class LspReferences extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.referenceInfos = new NativePtrDecoder()
      .decode(global.es2panda._getReferenceInfos(this.peer))
      .map((elPeer: KNativePointer) => {
        return new LspReferenceData(elPeer);
      });
  }
  readonly referenceInfos: LspReferenceData[];
}

export class LspTextSpan extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.start = global.es2panda._getTextSpanStart(peer);
    this.length = global.es2panda._getTextSpanLength(peer);
  }
  readonly start: KInt;
  readonly length: KInt;
}

export class LspSymbolDisplayPart extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.text = unpackString(global.es2panda._getDisplayPartsText(peer));
    this.kind = unpackString(global.es2panda._getDisplayPartsKind(peer));
  }
  readonly text: String;
  readonly kind: String;
}

export class LspQuickInfo extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.kind = unpackString(global.es2panda._getQuickInfoKind(peer));
    this.kindModifier = unpackString(global.es2panda._getQuickInfoKindModifier(peer));
    this.textSpan = new LspTextSpan(global.es2panda._getTextSpan(peer));
    this.fileName = unpackString(global.es2panda._getQuickInfoFileName(peer));
    this.displayParts = new NativePtrDecoder()
      .decode(global.es2panda._getSymbolDisplayPart(peer))
      .map((elPeer: KNativePointer) => {
        return new LspSymbolDisplayPart(elPeer);
      });
  }
  readonly kind: String;
  readonly kindModifier: String;
  readonly textSpan: LspTextSpan;
  readonly fileName: String;
  readonly displayParts: LspSymbolDisplayPart[];
}

export enum LspHighlightSpanKind {
  NONE,
  DEFINITION,
  REFERENCE,
  WRITTEN_REFERENCE
}

export class LspHighlightSpan extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getHighlightFileName(peer));
    this.textSpan = new LspTextSpan(global.es2panda._getHighlightTextSpan(peer));
    this.contextSpan = new LspTextSpan(global.es2panda._getHighlightContextSpan(peer));
    this.kind = global.es2panda._getHighlightKind(peer);
  }
  readonly fileName: String;
  readonly textSpan: LspTextSpan;
  readonly contextSpan: LspTextSpan;
  readonly kind: LspHighlightSpanKind;
}

export class LspDocumentHighlights extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getQuickInfoKind(peer));
    this.highlightSpans = new NativePtrDecoder()
      .decode(global.es2panda._getHighlightSpanFromHighlights(peer))
      .map((elPeer: KNativePointer) => {
        return new LspHighlightSpan(elPeer);
      });
  }
  readonly fileName: String;
  readonly highlightSpans: LspHighlightSpan[];
}

export class LspDocumentHighlightsReferences extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.documentHighlights = new NativePtrDecoder()
      .decode(global.es2panda._getDocumentHighlightsFromRef(peer))
      .map((elPeer: KNativePointer) => {
        return new LspDocumentHighlights(elPeer);
      });
  }
  readonly documentHighlights: LspDocumentHighlights[];
}

export enum LspCompletionEntryKind {
  TEXT = 1,
  METHOD = 2,
  FUNCTION = 3,
  CONSTRUCTOR = 4,
  FIELD = 5,
  VARIABLE = 6,
  CLASS = 7,
  INTERFACE = 8,
  MODULE = 9,
  PROPERTY = 10,
  UNIT = 11,
  VALUE = 12,
  ENUM = 13,
  KEYWORD = 14,
  SNIPPET = 15,
  COLOR = 16,
  FILE = 17,
  REFERENCE = 18,
  FOLDER = 19,
  ENUM_MEMBER = 20,
  CONSTANT = 21,
  STRUCT = 22,
  EVENT = 23,
  OPERATOR = 24,
  TYPE_PARAMETER = 25
}

export enum ResolutionStatus {
  RESOLVED,
  UNRESOLVED
}

export class LspCompletionEntryData extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.fileName = unpackString(global.es2panda._getFileNameFromEntryData(peer));
    this.namedExport = unpackString(global.es2panda._getNamedExportFromEntryData(peer));
    this.importDeclaration = unpackString(global.es2panda._getImportDeclarationFromEntryData(peer));
    this.status = global.es2panda._getStatusFromEntryData(peer);
  }
  readonly fileName: String;
  readonly namedExport: String;
  readonly importDeclaration: String;
  readonly status: ResolutionStatus;
}

export class LspCompletionEntry extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.name = unpackString(global.es2panda._getNameFromEntry(peer));
    this.sortText = unpackString(global.es2panda._getSortTextFromEntry(peer));
    this.insertText = unpackString(global.es2panda._getInsertTextFromEntry(peer));
    this.kind = global.es2panda._getKindFromEntry(peer);
    this.data = this.getCompletionEntryData(peer);
  }
  readonly name: String;
  readonly sortText: String;
  readonly insertText: String;
  readonly kind: LspCompletionEntryKind;
  readonly data: LspCompletionEntryData | null;
  private getCompletionEntryData(peer: KNativePointer): LspCompletionEntryData | null {
    const dataPtr = global.es2panda._getDataFromEntry(peer);
    if (dataPtr) {
      return new LspCompletionEntryData(dataPtr);
    } else {
      return null;
    }
  }
}

export class LspCompletionInfo extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.entries = new NativePtrDecoder()
      .decode(global.es2panda._getEntriesFromCompletionInfo(peer))
      .map((elPeer: KNativePointer) => {
        return new LspCompletionEntry(elPeer);
      });
  }
  readonly entries: LspCompletionEntry[];
}

export enum AccessKind {
  READ,
  WRITE,
  READWRITE
}

export class LspReferenceLocation extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.uri = unpackString(global.es2panda._getUriFromLocation(peer));
    this.start = global.es2panda._getStartFromLocation(peer);
    this.end = global.es2panda._getEndFromLocation(peer);
    this.accessKind = global.es2panda._getAccessKindFromLocation(peer);
  }
  readonly uri: String;
  readonly start: KInt;
  readonly end: KInt;
  readonly accessKind: AccessKind;
}

export class LspReferenceLocationList extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer);
    this.entries = new NativePtrDecoder()
      .decode(global.es2panda._getLocationFromList(peer))
      .map((elPeer: KNativePointer) => {
        return new LspReferenceLocation(elPeer);
      });
  }
  readonly entries: LspReferenceLocation[];
}

export class LspLineAndCharacter extends LspNode {
  readonly line: number;
  readonly character: number;
  constructor(peer: KNativePointer) {
    super(peer);
    this.line = global.es2panda._getLine(peer);
    this.character = global.es2panda._getChar(peer);
  }
}
