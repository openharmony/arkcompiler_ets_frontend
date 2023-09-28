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

export class TypeScriptDiagnosticsExtractor {
  constructor(public strictProgram: ts.Program, public nonStrictProgram: ts.Program) {
  }

  /**
   * Returns diagnostics which appear in strict compilation mode only
   */
  public getStrictDiagnostics(fileName: string): ts.Diagnostic[] {
    // applying filter is a workaround for tsc bug
    const strict = getAllDiagnostics(this.strictProgram, fileName)
                   .filter(diag => diag.length !== 0 && diag.start !== 0);
    const nonStrict = getAllDiagnostics(this.nonStrictProgram, fileName);

    // collect hashes for later easier comparison
    const nonStrictHashes = nonStrict.reduce((result, value) => {
      const hash = hashDiagnostic(value);
      if (hash) {
        result.add(hash);
      }
      return result;
    }, new Set<string>());
    // return diagnostics which weren't detected in non-strict mode
    return strict.filter(value => {
      const hash = hashDiagnostic(value);
      return (hash && !nonStrictHashes.has(hash));
    });
  }
}

function getAllDiagnostics(program: ts.Program, fileName: string): ts.Diagnostic[] {
  const sourceFile = program.getSourceFile(fileName);
  return program.getSemanticDiagnostics(sourceFile)
    .concat(program.getSyntacticDiagnostics(sourceFile))
    .filter(diag => diag.file === sourceFile);
}

function hashDiagnostic(diagnostic: ts.Diagnostic): string | undefined {
  if (diagnostic.start === undefined || diagnostic.length === undefined) {
    return undefined;
  }
  return `${diagnostic.code}%${diagnostic.start}%${diagnostic.length}`;
}
