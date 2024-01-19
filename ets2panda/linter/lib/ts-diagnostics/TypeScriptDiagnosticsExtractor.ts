/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import type * as ts from 'typescript';

/**
 * Returns diagnostics which appear in strict compilation mode only
 */
export function getStrictDiagnostics(
  strictProgram: ts.Program,
  nonStrictProgram: ts.Program,
  fileName: string,
  cancellationToken?: ts.CancellationToken
): ts.Diagnostic[] {
  // applying filter is a workaround for tsc bug
  const strict = getAllDiagnostics(strictProgram, fileName, cancellationToken).filter((diag) => {
    return !(diag.length === 0 && diag.start === 0);
  });
  const nonStrict = getAllDiagnostics(nonStrictProgram, fileName, cancellationToken);

  // collect hashes for later easier comparison
  const nonStrictHashes = nonStrict.reduce((result, value) => {
    const hash = hashDiagnostic(value);
    if (hash) {
      result.add(hash);
    }
    return result;
  }, new Set<string>());
  // return diagnostics which weren't detected in non-strict mode
  return strict.filter((value) => {
    const hash = hashDiagnostic(value);
    return hash && !nonStrictHashes.has(hash);
  });
}

function getAllDiagnostics(
  program: ts.Program,
  fileName: string,
  cancellationToken?: ts.CancellationToken
): ts.Diagnostic[] {
  const sourceFile = program.getSourceFile(fileName);
  return program.
    getSemanticDiagnostics(sourceFile, cancellationToken).
    concat(program.getSyntacticDiagnostics(sourceFile, cancellationToken)).
    filter((diag) => {
      return diag.file === sourceFile;
    });
}

function hashDiagnostic(diagnostic: ts.Diagnostic): string | undefined {
  if (diagnostic.start === undefined || diagnostic.length === undefined) {
    return undefined;
  }
  return `${diagnostic.code}%${diagnostic.start}%${diagnostic.length}`;
}
