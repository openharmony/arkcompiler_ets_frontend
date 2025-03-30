/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, softwareP
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as ts from 'typescript';
import * as path from 'node:path';
import type { ProblemInfo } from '../../lib/ProblemInfo';
import { ProblemSeverity } from '../../lib/ProblemSeverity';
import { TypeScriptLinter } from '../../lib/TypeScriptLinter';
import { getTscDiagnostics } from '../../lib/ts-diagnostics/GetTscDiagnostics';
import { ArkTSLinterTimePrinter, TimePhase } from '../ArkTSTimePrinter';
import { getScriptKind } from '../../lib/utils/functions/GetScriptKind';
import { SdkTSCCompiledProgram } from './SdkTSCCompiledProgram';
import { IncrementalLinterState } from './IncrementalLinter';
import { InteropTypescriptLinter } from '../../lib/InteropTypescriptLinter';
import type { SdkOptions } from './SdkOptions';
import type { LintParameter } from './LintParameter';
import { LibraryTypeCallDiagnosticChecker } from '../../lib/utils/functions/LibraryTypeCallDiagnosticChecker';

function makeDiag(
  category: ts.DiagnosticCategory,
  file: ts.SourceFile,
  length: number,
  problemInfo: ProblemInfo
): ts.Diagnostic {
  const code = problemInfo.ruleTag;
  const start = problemInfo.start;
  const messageText = problemInfo.rule;
  return { category, code, file, start, length, messageText };
}

export function translateDiag(srcFile: ts.SourceFile, problemInfo: ProblemInfo): ts.Diagnostic {
  const severity =
    problemInfo.severity === ProblemSeverity.ERROR ? ts.DiagnosticCategory.Error : ts.DiagnosticCategory.Warning;
  const length = problemInfo.end - problemInfo.start + 1;
  return makeDiag(severity, srcFile, length, problemInfo);
}

export function runArkTSLinter(
  tsBuilderProgram: ts.BuilderProgram,
  srcFile?: ts.SourceFile,
  buildInfoWriteFile?: ts.WriteFileCallback,
  arkTSVersion?: string,
  sdkOptions?: SdkOptions
): ts.Diagnostic[] {
  const diagnostics: ts.Diagnostic[] = [];
  const tscDiagnosticsLinter = new SdkTSCCompiledProgram(tsBuilderProgram);
  const program = tscDiagnosticsLinter.getProgram();
  const incrementalLinterState = new IncrementalLinterState(
    tsBuilderProgram,
    arkTSVersion,
    program.getCompilerOptions()
  );
  incrementalLinterState.updateProgramStateArkTSVersion(arkTSVersion);
  const timePrinterInstance = ArkTSLinterTimePrinter.getInstance();
  timePrinterInstance.appendTime(TimePhase.INIT);
  tscDiagnosticsLinter.updateCompilationDiagnostics();
  const srcFiles: ts.SourceFile[] = getSrcFiles(program, srcFile);
  const tscStrictDiagnostics = getTscDiagnostics(
    tscDiagnosticsLinter,
    srcFiles.filter((file) => {
      return incrementalLinterState.isFileChanged(file);
    })
  );
  timePrinterInstance.appendTime(TimePhase.GET_TSC_DIAGNOSTICS);
  const etsLoaderPath = program.getCompilerOptions().etsLoaderPath;
  const tsImportSendableEnable = program.getCompilerOptions().tsImportSendableEnable;
  const typeScriptLinter = createTypeScriptLinter(program, tscStrictDiagnostics, sdkOptions);
  LibraryTypeCallDiagnosticChecker.instance.rebuildTscDiagnostics(tscStrictDiagnostics);
  const interopTypescriptLinter = createInteropTypescriptLinter(program, !!sdkOptions?.isUseRtLogic);
  processFiles(srcFiles, {
    incrementalLinterState,
    typeScriptLinter,
    interopTypescriptLinter,
    tscStrictDiagnostics,
    diagnostics,
    etsLoaderPath,
    tsImportSendableEnable
  });
  timePrinterInstance.appendTime(TimePhase.LINT);
  if (buildInfoWriteFile) {
    IncrementalLinterState.emitBuildInfo(buildInfoWriteFile, tscDiagnosticsLinter.getBuilderProgram());
    timePrinterInstance.appendTime(TimePhase.EMIT_BUILD_INFO);
  }
  releaseResources();
  return diagnostics;
}

function processFiles(srcFiles: ts.SourceFile[], lintParameter: LintParameter): void {
  for (const fileToLint of srcFiles) {
    const scriptKind = getScriptKind(fileToLint);
    if (scriptKind !== ts.ScriptKind.ETS && scriptKind !== ts.ScriptKind.TS) {
      continue;
    }

    const currentDiagnostics = getDiagnostic(fileToLint, scriptKind, lintParameter);
    lintParameter.diagnostics.push(...currentDiagnostics);
    lintParameter.incrementalLinterState.updateDiagnostics(fileToLint, currentDiagnostics);
  }
}

function getDiagnostic(
  fileToLint: ts.SourceFile,
  scriptKind: ts.ScriptKind,
  lintParameter: LintParameter
): ts.Diagnostic[] {
  let currentDiagnostics: ts.Diagnostic[] = [];
  if (lintParameter.incrementalLinterState.isFileChanged(fileToLint)) {
    if (scriptKind === ts.ScriptKind.ETS) {
      lintParameter.typeScriptLinter.lint(fileToLint);

      // Get list of bad nodes from the current run.
      currentDiagnostics = lintParameter.tscStrictDiagnostics.get(path.normalize(fileToLint.fileName)) ?? [];
      lintParameter.typeScriptLinter.problemsInfos.forEach((x) => {
        return currentDiagnostics.push(translateDiag(fileToLint, x));
      });
      lintParameter.typeScriptLinter.problemsInfos.length = 0;
    } else {
      if (
        path.basename(fileToLint.fileName).toLowerCase().
          indexOf('@kit.') === 0 ||
        ts.isOHModules(fileToLint.fileName)
      ) {
        return currentDiagnostics;
      }

      const isInSdk = lintParameter.etsLoaderPath ?
        path.
          normalize(fileToLint.fileName).
        // @ts-expect-error : should expect method
          indexOf(ts.resolvePath(lintParameter.etsLoaderPath, '../..')) === 0 :
        false;
      if (!lintParameter.tsImportSendableEnable && !isInSdk) {
        return currentDiagnostics;
      }

      lintParameter.interopTypescriptLinter.lint(fileToLint);
      lintParameter.interopTypescriptLinter.problemsInfos.forEach((x) => {
        return currentDiagnostics.push(translateDiag(fileToLint, x));
      });
      lintParameter.interopTypescriptLinter.problemsInfos.length = 0;
    }
  } else {
    // Get diagnostics from old run.
    currentDiagnostics = lintParameter.incrementalLinterState.getOldDiagnostics(fileToLint);
  }
  return currentDiagnostics;
}

function getSrcFiles(program: ts.Program, srcFile?: ts.SourceFile): ts.SourceFile[] {
  let srcFiles: ts.SourceFile[] = [];
  if (srcFile) {
    srcFiles.push(srcFile);
  } else {
    srcFiles = program.getSourceFiles() as ts.SourceFile[];
  }
  return srcFiles;
}

function createTypeScriptLinter(
  program: ts.Program,
  tscStrictDiagnostics: Map<string, ts.Diagnostic[]>,
  sdkOptions?: SdkOptions
): TypeScriptLinter {
  TypeScriptLinter.initGlobals();
  return new TypeScriptLinter(
    program.getLinterTypeChecker(),
    {
      ideMode: true,
      enableAutofix: sdkOptions?.needAutoFix,
      useRtLogic: sdkOptions?.isUseRtLogic,
      compatibleSdkVersion: program.getCompilerOptions().compatibleSdkVersion,
      compatibleSdkVersionStage: program.getCompilerOptions().compatibleSdkVersionStage
    },
    tscStrictDiagnostics
  );
}

function createInteropTypescriptLinter(program: ts.Program, useRtLogic: boolean): InteropTypescriptLinter {
  InteropTypescriptLinter.initGlobals();
  return new InteropTypescriptLinter(
    program.getLinterTypeChecker(),
    program.getCompilerOptions(),
    {
      ideMode: true,
      useRtLogic: useRtLogic
    },
    program.getCompilerOptions().etsLoaderPath
  );
}

// Reclaim memory for Hvigor with "no-parallel" and "daemon".
function releaseResources(): void {}
