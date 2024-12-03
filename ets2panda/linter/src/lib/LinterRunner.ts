/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

import * as path from 'node:path';
import type * as ts from 'typescript';
import type { CommandLineOptions } from './CommandLineOptions';
import { faultsAttrs } from './FaultAttrs';
import { faultDesc } from './FaultDesc';
import { InteropTypescriptLinter } from './InteropTypescriptLinter';
import type { LinterConfig } from './LinterConfig';
import type { LinterOptions } from './LinterOptions';
import type { LintRunResult } from './LintRunResult';
import { Logger } from './Logger';
import type { ProblemInfo } from './ProblemInfo';
import { ProblemSeverity } from './ProblemSeverity';
import { FaultID } from './Problems';
import { TypeScriptLinter } from './TypeScriptLinter';
import { getTscDiagnostics } from './ts-diagnostics/GetTscDiagnostics';
import { transformTscDiagnostics } from './ts-diagnostics/TransformTscDiagnostics';
import {
  ARKTS_IGNORE_DIRS_NO_OH_MODULES,
  ARKTS_IGNORE_DIRS_OH_MODULES,
  ARKTS_IGNORE_FILES
} from './utils/consts/ArktsIgnorePaths';
import { mergeArrayMaps } from './utils/functions/MergeArrayMaps';
import { clearPathHelperCache, pathContainsDirectory } from './utils/functions/PathHelper';
import { LibraryTypeCallDiagnosticChecker } from './utils/functions/LibraryTypeCallDiagnosticChecker';

export function consoleLog(linterOptions: LinterOptions, ...args: unknown[]): void {
  if (linterOptions.ideMode) {
    return;
  }
  let outLine = '';
  for (let k = 0; k < args.length; k++) {
    outLine += `${args[k]} `;
  }
  Logger.info(outLine);
}

function prepareInputFilesList(cmdOptions: CommandLineOptions): string[] {
  let inputFiles = cmdOptions.inputFiles;
  if (!cmdOptions.parsedConfigFile) {
    return inputFiles;
  }

  inputFiles = cmdOptions.parsedConfigFile.fileNames;
  if (cmdOptions.inputFiles.length <= 0) {
    return inputFiles;
  }

  /*
   * Apply linter only to the project source files that are specified
   * as a command-line arguments. Other source files will be discarded.
   */
  const cmdInputsResolvedPaths = cmdOptions.inputFiles.map((x) => {
    return path.resolve(x);
  });
  const configInputsResolvedPaths = inputFiles.map((x) => {
    return path.resolve(x);
  });
  inputFiles = configInputsResolvedPaths.filter((x) => {
    return cmdInputsResolvedPaths.some((y) => {
      return x === y;
    });
  });

  return inputFiles;
}

function countProblems(linter: TypeScriptLinter | InteropTypescriptLinter): [number, number] {
  let errorNodesTotal = 0;
  let warningNodes = 0;
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    switch (faultsAttrs[i].severity) {
      case ProblemSeverity.ERROR:
        errorNodesTotal += linter.nodeCounters[i];
        break;
      case ProblemSeverity.WARNING:
        warningNodes += linter.nodeCounters[i];
        break;
      default:
    }
  }

  return [errorNodesTotal, warningNodes];
}

export function lint(config: LinterConfig, etsLoaderPath: string | undefined): LintRunResult {
  const { cmdOptions, tscCompiledProgram } = config;
  const tsProgram = tscCompiledProgram.getProgram();
  const options = cmdOptions.linterOptions;

  // Prepare list of input files for linter and retrieve AST for those files.
  let inputFiles = prepareInputFilesList(cmdOptions);
  inputFiles = inputFiles.filter((input) => {
    return shouldProcessFile(options, input);
  });
  const srcFiles: ts.SourceFile[] = [];
  for (const inputFile of inputFiles) {
    const srcFile = tsProgram.getSourceFile(inputFile);
    if (srcFile) {
      srcFiles.push(srcFile);
    }
  }

  const tscStrictDiagnostics = getTscDiagnostics(tscCompiledProgram, srcFiles);
  LibraryTypeCallDiagnosticChecker.rebuildTscDiagnostics(tscStrictDiagnostics);
  const linter = !options.interopCheckMode ?
    new TypeScriptLinter(tsProgram.getTypeChecker(), options, tscStrictDiagnostics) :
    new InteropTypescriptLinter(tsProgram.getTypeChecker(), tsProgram.getCompilerOptions(), options, etsLoaderPath);
  const { errorNodes, problemsInfos } = lintFiles(srcFiles, linter);
  consoleLog(options, '\n\n\nFiles scanned: ', srcFiles.length);
  consoleLog(options, '\nFiles with problems: ', errorNodes);

  const [errorNodesTotal, warningNodes] = countProblems(linter);
  logTotalProblemsInfo(errorNodesTotal, warningNodes, linter);
  logProblemsPercentageByFeatures(linter);

  freeMemory();

  return {
    errorNodes: errorNodesTotal,
    problemsInfos: mergeArrayMaps(problemsInfos, transformTscDiagnostics(tscStrictDiagnostics))
  };
}

function lintFiles(srcFiles: ts.SourceFile[], linter: TypeScriptLinter | InteropTypescriptLinter): LintRunResult {
  let problemFiles = 0;
  const problemsInfos: Map<string, ProblemInfo[]> = new Map();

  for (const srcFile of srcFiles) {
    const prevVisitedNodes = linter.totalVisitedNodes;
    const prevErrorLines = linter.totalErrorLines;
    const prevWarningLines = linter.totalWarningLines;
    linter.errorLineNumbersString = '';
    linter.warningLineNumbersString = '';
    const nodeCounters: number[] = [];

    for (let i = 0; i < FaultID.LAST_ID; i++) {
      nodeCounters[i] = linter.nodeCounters[i];
    }

    linter.lint(srcFile);
    // save results and clear problems array
    problemsInfos.set(path.normalize(srcFile.fileName), [...linter.problemsInfos]);
    linter.problemsInfos.length = 0;

    // print results for current file
    const fileVisitedNodes = linter.totalVisitedNodes - prevVisitedNodes;
    const fileErrorLines = linter.totalErrorLines - prevErrorLines;
    const fileWarningLines = linter.totalWarningLines - prevWarningLines;

    problemFiles = countProblemFiles(
      nodeCounters,
      problemFiles,
      srcFile,
      fileVisitedNodes,
      fileErrorLines,
      fileWarningLines,
      linter
    );
  }

  return {
    errorNodes: problemFiles,
    problemsInfos: problemsInfos
  };
}

// eslint-disable-next-line max-lines-per-function, max-params
function countProblemFiles(
  nodeCounters: number[],
  filesNumber: number,
  tsSrcFile: ts.SourceFile,
  fileNodes: number,
  fileErrorLines: number,
  fileWarningLines: number,
  linter: TypeScriptLinter | InteropTypescriptLinter
): number {
  let errorNodes = 0;
  let warningNodes = 0;
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    const nodeCounterDiff = linter.nodeCounters[i] - nodeCounters[i];
    switch (faultsAttrs[i].severity) {
      case ProblemSeverity.ERROR:
        errorNodes += nodeCounterDiff;
        break;
      case ProblemSeverity.WARNING:
        warningNodes += nodeCounterDiff;
        break;
      default:
    }
  }
  if (errorNodes > 0) {
    // eslint-disable-next-line no-param-reassign
    filesNumber++;
    const errorRate = (errorNodes / fileNodes * 100).toFixed(2);
    const warningRate = (warningNodes / fileNodes * 100).toFixed(2);
    consoleLog(linter.options, tsSrcFile.fileName, ': ', '\n\tError lines: ', linter.errorLineNumbersString);
    consoleLog(linter.options, tsSrcFile.fileName, ': ', '\n\tWarning lines: ', linter.warningLineNumbersString);
    consoleLog(
      linter.options,
      '\n\tError constructs (%): ',
      errorRate,
      '\t[ of ',
      fileNodes,
      ' constructs ], \t',
      fileErrorLines,
      ' lines'
    );
    consoleLog(
      linter.options,
      '\n\tWarning constructs (%): ',
      warningRate,
      '\t[ of ',
      fileNodes,
      ' constructs ], \t',
      fileWarningLines,
      ' lines'
    );
  }

  return filesNumber;
}

function logTotalProblemsInfo(
  errorNodes: number,
  warningNodes: number,
  linter: TypeScriptLinter | InteropTypescriptLinter
): void {
  const errorRate = (errorNodes / linter.totalVisitedNodes * 100).toFixed(2);
  const warningRate = (warningNodes / linter.totalVisitedNodes * 100).toFixed(2);
  consoleLog(linter.options, '\nTotal error constructs (%): ', errorRate);
  consoleLog(linter.options, '\nTotal warning constructs (%): ', warningRate);
  consoleLog(linter.options, '\nTotal error lines:', linter.totalErrorLines, ' lines\n');
  consoleLog(linter.options, '\nTotal warning lines:', linter.totalWarningLines, ' lines\n');
}

function logProblemsPercentageByFeatures(linter: TypeScriptLinter | InteropTypescriptLinter): void {
  consoleLog(linter.options, '\nPercent by features: ');
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    const nodes = linter.nodeCounters[i];
    const lines = linter.lineCounters[i];
    const pecentage = (nodes / linter.totalVisitedNodes * 100).toFixed(2).padEnd(7, ' ');

    consoleLog(linter.options, faultDesc[i].padEnd(55, ' '), pecentage, '[', nodes, ' constructs / ', lines, ' lines]');
  }
}

function shouldProcessFile(options: LinterOptions, fileFsPath: string): boolean {
  if (
    ARKTS_IGNORE_FILES.some((ignore) => {
      return path.basename(fileFsPath) === ignore;
    })
  ) {
    return false;
  }

  if (
    ARKTS_IGNORE_DIRS_NO_OH_MODULES.some((ignore) => {
      return pathContainsDirectory(path.resolve(fileFsPath), ignore);
    })
  ) {
    return false;
  }

  return (
    !pathContainsDirectory(path.resolve(fileFsPath), ARKTS_IGNORE_DIRS_OH_MODULES) ||
    !!options.isFileFromModuleCb?.(fileFsPath)
  );
}

function freeMemory(): void {
  clearPathHelperCache();
}
