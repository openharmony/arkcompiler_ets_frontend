/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
  LibraryTypeCallDiagnosticChecker.instance.rebuildTscDiagnostics(tscStrictDiagnostics);
  const lintParam: LintParameter = {
    incrementalLinterState,
    tscStrictDiagnostics,
    diagnostics,
    etsLoaderPath,
    tsImportSendableEnable,
    program,
    sdkOptions
  };
  processFiles(srcFiles, lintParam, tscStrictDiagnostics);
  timePrinterInstance.appendTime(TimePhase.LINT);
  if (buildInfoWriteFile) {
    IncrementalLinterState.emitBuildInfo(buildInfoWriteFile, tscDiagnosticsLinter.getBuilderProgram());
    timePrinterInstance.appendTime(TimePhase.EMIT_BUILD_INFO);
  }
  releaseResources();
  return diagnostics;
}

function processFiles(
  srcFiles: ts.SourceFile[],
  lintParameter: LintParameter,
  tscStrictDiagnostics: Map<string, ts.Diagnostic[]>
): void {
  for (const fileToLint of srcFiles) {
    const scriptKind = getScriptKind(fileToLint);
    if (scriptKind !== ts.ScriptKind.ETS && scriptKind !== ts.ScriptKind.TS) {
      continue;
    }

    const currentDiagnostics = getDiagnostic(fileToLint, scriptKind, lintParameter, tscStrictDiagnostics);
    lintParameter.diagnostics.push(...currentDiagnostics);
    lintParameter.incrementalLinterState.updateDiagnostics(fileToLint, currentDiagnostics);
  }
}

function getDiagnostic(
  fileToLint: ts.SourceFile,
  scriptKind: ts.ScriptKind,
  lintParameter: LintParameter,
  tscStrictDiagnostics: Map<string, ts.Diagnostic[]>
): ts.Diagnostic[] {
  let currentDiagnostics: ts.Diagnostic[] = [];
  if (lintParameter.incrementalLinterState.isFileChanged(fileToLint)) {
    if (scriptKind === ts.ScriptKind.ETS) {
      const typeScriptLinter = createTypeScriptLinter(fileToLint, lintParameter, tscStrictDiagnostics);
      typeScriptLinter.lint();

      // Get list of bad nodes from the current run.
      currentDiagnostics = lintParameter.tscStrictDiagnostics.get(path.normalize(fileToLint.fileName)) ?? [];
      typeScriptLinter.problemsInfos.forEach((x) => {
        return currentDiagnostics.push(translateDiag(fileToLint, x));
      });
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

      const interopTypescriptLinter = createInteropTypescriptLinter(lintParameter.program, fileToLint, lintParameter);
      interopTypescriptLinter.lint();
      interopTypescriptLinter.problemsInfos.forEach((x) => {
        return currentDiagnostics.push(translateDiag(fileToLint, x));
      });
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
  sourceFile: ts.SourceFile,
  lintParameter: LintParameter,
  tscStrictDiagnostics: Map<string, ts.Diagnostic[]>
): TypeScriptLinter {
  TypeScriptLinter.initGlobals();
  return new TypeScriptLinter(
    lintParameter.program.getLinterTypeChecker(),
    {
      enableAutofix: lintParameter.sdkOptions?.needAutoFix,
      useRtLogic: lintParameter.sdkOptions?.isUseRtLogic,
      compatibleSdkVersion: lintParameter.program.getCompilerOptions().compatibleSdkVersion,
      compatibleSdkVersionStage: lintParameter.program.getCompilerOptions().compatibleSdkVersionStage
    },
    sourceFile,
    tscStrictDiagnostics
  );
}

function createInteropTypescriptLinter(
  program: ts.Program,
  sourceFile: ts.SourceFile,
  lintParameter: LintParameter
): InteropTypescriptLinter {
  InteropTypescriptLinter.initGlobals();
  return new InteropTypescriptLinter(
    program.getLinterTypeChecker(),
    program.getCompilerOptions(),
    {
      etsLoaderPath: lintParameter.etsLoaderPath,
      useRtLogic: lintParameter.sdkOptions?.isUseRtLogic
    },
    sourceFile
  );
}

// Reclaim memory for Hvigor with "no-parallel" and "daemon".
function releaseResources(): void {}
