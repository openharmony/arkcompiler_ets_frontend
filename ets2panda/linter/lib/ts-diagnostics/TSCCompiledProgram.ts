/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
import type { LintOptions } from '../LintOptions';
import { TypeScriptDiagnosticsExtractor } from './TypeScriptDiagnosticsExtractor';
import { Compiler } from '../Compiler';
import { FaultID } from '../Problems';
import { faultsAttrs } from '../FaultAttrs';

export interface TSCCompiledProgram {
  getOriginalProgram: () => ts.Program;
  getStrictDiagnostics: (fileName: string) => ts.Diagnostic[];
}

export class TSCCompiledProgramSimple implements TSCCompiledProgram {
  private readonly tsProgram: ts.Program;

  constructor(program: ts.Program) {
    this.tsProgram = program;
  }

  getOriginalProgram(): ts.Program {
    return this.tsProgram;
  }

  getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    void fileName;
    void this;
    return [];
  }
}

export class TSCCompiledProgramWithDiagnostics implements TSCCompiledProgram {
  private readonly diagnosticsExtractor: TypeScriptDiagnosticsExtractor;
  private readonly wasStrict: boolean;
  private readonly cachedDiagnostics: Map<string, ts.Diagnostic[]>;

  constructor(program: ts.Program, options: LintOptions) {
    const { strict, nonStrict, wasStrict } = getTwoCompiledVersions(program, options);
    this.diagnosticsExtractor = new TypeScriptDiagnosticsExtractor(strict, nonStrict);
    this.wasStrict = wasStrict;
    this.cachedDiagnostics = new Map();
  }

  getOriginalProgram(): ts.Program {
    return this.wasStrict ? this.diagnosticsExtractor.strictProgram : this.diagnosticsExtractor.nonStrictProgram;
  }

  getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    const cachedDiagnostic = this.cachedDiagnostics.get(fileName);
    if (cachedDiagnostic) {
      return cachedDiagnostic;
    }
    const diagnostic = this.diagnosticsExtractor.getStrictDiagnostics(fileName);
    this.cachedDiagnostics.set(fileName, diagnostic);
    return diagnostic;
  }
}

export function getStrictOptions(): {
  strictNullChecks: boolean;
  strictFunctionTypes: boolean;
  strictPropertyInitialization: boolean;
  noImplicitReturns: boolean;
} {
  return {
    strictNullChecks: true,
    strictFunctionTypes: true,
    strictPropertyInitialization: true,
    noImplicitReturns: true
  };
}

function isStrict(compilerOptions: ts.CompilerOptions): boolean {
  const strictOptions = getStrictOptions();
  let wasStrict = false;
  // wasStrict evaluates true if any of the strict options was set
  Object.keys(strictOptions).forEach((x) => {
    wasStrict = wasStrict || !!compilerOptions[x];
  });
  return wasStrict;
}

function getTwoCompiledVersions(
  program: ts.Program,
  options: LintOptions
): { strict: ts.Program; nonStrict: ts.Program; wasStrict: boolean } {
  const compilerOptions = program.getCompilerOptions();
  const inversedOptions = getInversedOptions(compilerOptions);
  const withInversedOptions = Compiler.compile(options, inversedOptions);
  const wasStrict = isStrict(compilerOptions);
  return {
    strict: wasStrict ? program : withInversedOptions,
    nonStrict: wasStrict ? withInversedOptions : program,
    wasStrict: wasStrict
  };
}

function getInversedOptions(compilerOptions: ts.CompilerOptions): ts.CompilerOptions {
  const newOptions = { ...compilerOptions };
  const wasStrict = isStrict(compilerOptions);
  Object.keys(getStrictOptions()).forEach((key) => {
    newOptions[key] = !wasStrict;
  });
  return newOptions;
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
    severity: ProblemSeverity.ERROR,
    problem: FaultID[faultId],
    suggest: messageText,
    rule: messageText,
    ruleTag: faultsAttrs[faultId] ? faultsAttrs[faultId].cookBookRef : 0,
    autofixable: false
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
