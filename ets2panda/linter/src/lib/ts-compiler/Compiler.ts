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
import type { CommandLineOptions } from '../CommandLineOptions';
import { formTscOptions } from './FormTscOptions';
import { logTscDiagnostic } from '../utils/functions/LogTscDiagnostic';
import type { LinterConfig } from '../LinterConfig';
import { TSCCompiledProgramSimple, TSCCompiledProgramWithDiagnostics } from '../ts-diagnostics/TSCCompiledProgram';
import { Logger } from '../Logger';

export type createProgramCallback = (createProgramOptions: ts.CreateProgramOptions) => ts.Program;

function compile(
  cmdOptions: CommandLineOptions,
  overrideCompilerOptions: ts.CompilerOptions,
  createProgramCb?: createProgramCallback
): ts.Program {
  const createProgramOptions = formTscOptions(cmdOptions, overrideCompilerOptions);
  const program = createProgramCb ? createProgramCb(createProgramOptions) : ts.createProgram(createProgramOptions);
  // Log Tsc errors if needed
  if (cmdOptions.logTscErrors) {
    const diagnostics = ts.getPreEmitDiagnostics(program);
    logTscDiagnostic(diagnostics, Logger.info);
  }
  return program;
}

export function compileLintOptions(
  cmdOptions: CommandLineOptions,
  createProgramCb?: createProgramCallback
): LinterConfig {
  const linterConfig = cmdOptions.disableStrictDiagnostics ?
    compileSimpleProgram(cmdOptions, createProgramCb) :
    compileWithStrictDiagnostics(cmdOptions, createProgramCb);

  linterConfig.cmdOptions.linterOptions.etsLoaderPath = getEtsLoaderPath(linterConfig);
  return linterConfig;
}

function compileSimpleProgram(cmdOptions: CommandLineOptions, createProgramCb?: createProgramCallback): LinterConfig {
  const program = compile(cmdOptions, getOverrideCompilerOptions(true), createProgramCb);
  return {
    cmdOptions: cmdOptions,
    tscCompiledProgram: new TSCCompiledProgramSimple(program)
  };
}

function compileWithStrictDiagnostics(
  cmdOptions: CommandLineOptions,
  createProgramCb?: createProgramCallback
): LinterConfig {
  const strict = compile(cmdOptions, getOverrideCompilerOptions(true), createProgramCb);
  const nonStrict = compile(cmdOptions, getOverrideCompilerOptions(false), createProgramCb);
  return {
    cmdOptions: cmdOptions,
    tscCompiledProgram: new TSCCompiledProgramWithDiagnostics(strict, nonStrict, cmdOptions.inputFiles)
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

export function getEtsLoaderPath(linterConfig: LinterConfig): string | undefined {
  const tsProgram = linterConfig.tscCompiledProgram.getProgram();
  return tsProgram.getCompilerOptions().etsLoaderPath;
}
