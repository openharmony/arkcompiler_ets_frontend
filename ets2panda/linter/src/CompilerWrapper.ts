/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
import { logTscDiagnostic } from './utils/functions/LogTscDiagnostic';
import { consoleLog } from './TypeScriptLinter';
import { formTscOptions } from './ts-compiler/FormTscOptions';
import { LintOptions } from './LintOptions';

export function compile(options: LintOptions, extraOptions?: any): ts.Program {
  const createProgramOptions = formTscOptions(options.cmdOptions, extraOptions);
  const program = ts.createProgram(createProgramOptions);
  // Log Tsc errors if needed
  if (options.cmdOptions.logTscErrors) {
    const diagnostics = ts.getPreEmitDiagnostics(program);
    logTscDiagnostic(diagnostics, consoleLog);
    diagnostics.forEach((diagnostic) => {
      if (diagnostic.file && diagnostic.start) {
        const { line, character } = ts.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start);
        const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n');
        consoleLog(`${diagnostic.file.fileName} (${line + 1}, ${character + 1}): ${message}`);
      } else {
        consoleLog(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
      }
    });
  }
  return program;
}
