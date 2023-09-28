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
import { ProblemInfo } from '../ProblemInfo';
import { ProblemSeverity } from '../ProblemSeverity';
import { LintOptions } from '../LintOptions';
import { TypeScriptDiagnosticsExtractor } from './TypeScriptDiagnosticsExtractor';
import { compile } from '../CompilerWrapper';
import { getNodeOrLineEnd } from '../Utils';
import { FaultID, faultsAttrs } from '../Problems';

export class TSCCompiledProgram {
  private diagnosticsExtractor: TypeScriptDiagnosticsExtractor;
  private wasStrict: boolean;

  constructor(program: ts.Program, options: LintOptions) {
    const { strict, nonStrict, wasStrict } = getTwoCompiledVersions(program, options);
    this.diagnosticsExtractor = new TypeScriptDiagnosticsExtractor(strict, nonStrict);
    this.wasStrict = wasStrict;
  }

  public getOriginalProgram(): ts.Program {
    return this.wasStrict
      ? this.diagnosticsExtractor.strictProgram
      : this.diagnosticsExtractor.nonStrictProgram;
  }

  public getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    return this.diagnosticsExtractor.getStrictDiagnostics(fileName);
  }
}

export function getStrictOptions(strict: boolean = true) {
  return {
    strictNullChecks: strict,
    strictFunctionTypes: strict,
    strictPropertyInitialization: strict,
    noImplicitReturns: strict,
  }
}

function getTwoCompiledVersions(
  program: ts.Program,
  options: LintOptions,
): { strict: ts.Program; nonStrict: ts.Program; wasStrict: boolean } {
  const compilerOptions = { ...program.getCompilerOptions()};

  const wasStrict = inverseStrictOptions(compilerOptions);
  const inversedOptions = getStrictOptions(!wasStrict);
  const withInversedOptions = compile(options, inversedOptions);

  return {
    strict: wasStrict ? program : withInversedOptions,
    nonStrict: wasStrict ? withInversedOptions : program,
    wasStrict: wasStrict,
  }
}

/**
 * Returns true if options were initially strict
 */
function inverseStrictOptions(compilerOptions: ts.CompilerOptions): boolean {
  const strictOptions = getStrictOptions();
  let wasStrict = false;
  Object.keys(strictOptions).forEach(x => {
    wasStrict = wasStrict || !!compilerOptions[x];
  });
  // wasStrict evaluates true if any of the strict options was set
  return wasStrict;
}

export function transformDiagnostic(diagnostic: ts.Diagnostic): ProblemInfo {
  const { line, column } = getLineAndColumn(diagnostic);
  const startPos = diagnostic.start!;
  const endPos = startPos + diagnostic.length!;
  const messageText = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
  const faultId = FaultID.StrictDiagnostic;

  return {
    line: line,
    column: column,
    endColumn: getNodeOrLineEnd(diagnostic.file!, startPos, endPos, line),
    start: startPos,
    end: endPos,
    type: 'StrictModeError',
    severity: ProblemSeverity.ERROR,  // expect strict options to always present
    problem: FaultID[faultId],
    suggest: messageText,
    rule: messageText,
    ruleTag: faultsAttrs[faultId] ? Number(faultsAttrs[faultId].cookBookRef) : 0,
    autofixable: false,
  };
}

/**
 * Returns line and column of the diagnostic's node, counts from 1
 */
function getLineAndColumn(diagnostic: ts.Diagnostic): { line: number; column: number } {
  let { line, character } = diagnostic.file!.getLineAndCharacterOfPosition(diagnostic.start!);
  // TSC counts lines and columns from zero
  return {
    line: line + 1,
    column: character + 1,
  }
}
