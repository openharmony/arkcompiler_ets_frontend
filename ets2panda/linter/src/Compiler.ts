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

import * as ts from 'typescript';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { formTscOptions } from './ts-compiler/FormTscOptions';
import { logTscDiagnostic } from '../lib/utils/functions/LogTscDiagnostic';
import { consoleLog } from '../lib/TypeScriptLinter';
import type { LintOptions } from '../lib/LintOptions';
import { TSCCompiledProgramWithDiagnostics } from '../lib/ts-diagnostics/TSCCompiledProgram';

function compile(cmdOptions: CommandLineOptions, overrideCompilerOptions: ts.CompilerOptions): ts.Program {
  const createProgramOptions = formTscOptions(cmdOptions, overrideCompilerOptions);
  const program = ts.createProgram(createProgramOptions);
  // Log Tsc errors if needed
  if (cmdOptions.logTscErrors) {
    const diagnostics = ts.getPreEmitDiagnostics(program);
    logTscDiagnostic(diagnostics, consoleLog);
  }
  return program;
}

export function compileLintOptions(cmdOptions: CommandLineOptions): LintOptions {
  const strict = compile(cmdOptions, getOverrideCompilerOptions(true));
  const nonStrict = compile(cmdOptions, getOverrideCompilerOptions(false));
  return {
    cmdOptions: cmdOptions,
    tscCompiledProgram: new TSCCompiledProgramWithDiagnostics(strict, nonStrict, cmdOptions.inputFiles),
    isEtsFile: true
  };
}

function getOverrideCompilerOptions(strict: boolean): ts.CompilerOptions {
  return {
    strict: false,
    alwaysStrict: false,
    noImplicitAny: false,
    noImplicitThis: false,
    strictBindCallApply: false,
    useUnknownInCatchVariables: false,
    strictNullChecks: strict,
    strictFunctionTypes: strict,
    strictPropertyInitialization: strict,
    noImplicitReturns: strict
  };
}
