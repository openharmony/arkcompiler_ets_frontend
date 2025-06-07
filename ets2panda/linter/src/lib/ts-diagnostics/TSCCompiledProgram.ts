/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

import * as ts from 'typescript';
import type { ProblemInfo } from '../ProblemInfo';
import { ProblemSeverity } from '../ProblemSeverity';
import { getStrictDiagnostics } from './TypeScriptDiagnosticsExtractor';
import { FaultID } from '../Problems';
import { faultsAttrs } from '../FaultAttrs';

export interface TSCCompiledProgram {
  getProgram: () => ts.Program;
  getStrictDiagnostics: (fileName: string) => ts.Diagnostic[];
}

export class TSCCompiledProgramSimple implements TSCCompiledProgram {
  private readonly program: ts.Program;

  constructor(program: ts.Program) {
    this.program = program;
  }

  getProgram(): ts.Program {
    return this.program;
  }

  getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    void this;
    void fileName;
    return [];
  }
}

export type ProgressCallback = (message: string) => void;

export class TSCCompiledProgramWithDiagnostics implements TSCCompiledProgram {
  private readonly program: ts.Program;
  private readonly cachedDiagnostics: Map<string, ts.Diagnostic[]> = new Map();

  constructor(
    strict: ts.Program,
    nonStrict: ts.Program,
    inputFiles: string[],
    cancellationToken?: ts.CancellationToken,
    progressCb?: ProgressCallback
  ) {
    this.program = strict;

    inputFiles.forEach((fileName) => {
      progressCb?.(fileName);

      const sourceFile = this.program.getSourceFile(fileName);
      if (sourceFile !== undefined) {
        this.cachedDiagnostics.set(
          sourceFile.fileName,
          getStrictDiagnostics(strict, nonStrict, sourceFile.fileName, cancellationToken)
        );
      }
    });
  }

  getProgram(): ts.Program {
    return this.program;
  }

  getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    return this.cachedDiagnostics.get(fileName) ?? [];
  }
}

export function transformDiagnostic(diagnostic: ts.Diagnostic): ProblemInfo {
  const startPos = diagnostic.start!;
  const start = getLineAndColumn(diagnostic.file!, startPos);
  const endPos = startPos + diagnostic.length!;
  const end = getLineAndColumn(diagnostic.file!, endPos);
  const messageText = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
  const faultId = FaultID.StrictDiagnostic;

  return {
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    start: startPos,
    end: endPos,
    type: 'StrictModeError',
    // expect strict options to always present
    faultId: faultId,
    severity: diagnostic.category === ts.DiagnosticCategory.Warning ? ProblemSeverity.WARNING : ProblemSeverity.ERROR,
    problem: FaultID[faultId],
    suggest: messageText,
    rule: messageText,
    ruleTag: faultsAttrs[faultId] ? faultsAttrs[faultId].cookBookRef : 0
  };
}

/**
 * Returns line and column of the position, counts from 1
 */
function getLineAndColumn(file: ts.SourceFile, position: number): { line: number; column: number } {
  const { line, character } = file.getLineAndCharacterOfPosition(position);
  // TSC counts lines and columns from zero
  return {
    line: line + 1,
    column: character + 1
  };
}
