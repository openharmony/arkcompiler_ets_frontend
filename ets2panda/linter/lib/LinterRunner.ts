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

import type * as ts from 'typescript';
import type { ProblemInfo } from './ProblemInfo';
import { TypeScriptLinter, consoleLog } from './TypeScriptLinter';
import { FaultID } from './Problems';
import { faultDesc } from './FaultDesc';
import { faultsAttrs } from './FaultAttrs';
import type { LintRunResult } from './LintRunResult';
import * as path from 'node:path';
import type { LintOptions } from './LintOptions';
import type { CommandLineOptions } from './CommandLineOptions';
import { mergeArrayMaps } from './utils/functions/MergeArrayMaps';
import { getTscDiagnostics } from './ts-diagnostics/GetTscDiagnostics';
import { transformTscDiagnostics } from './ts-diagnostics/TransformTscDiagnostics';
import {
  ARKTS_IGNORE_DIRS_NO_OH_MODULES,
  ARKTS_IGNORE_DIRS_OH_MODULES,
  ARKTS_IGNORE_FILES
} from './utils/consts/ArktsIgnorePaths';
import { pathContainsDirectory } from './utils/functions/PathHelper';
import { ProblemSeverity } from './ProblemSeverity';

function prepareInputFilesList(cmdOptions: CommandLineOptions): string[] {
  let inputFiles = cmdOptions.inputFiles;
  if (cmdOptions.parsedConfigFile) {
    inputFiles = cmdOptions.parsedConfigFile.fileNames;
    if (cmdOptions.inputFiles.length > 0) {

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
    }
  }

  return inputFiles;
}

function countProblems(linter: TypeScriptLinter): [number, number] {
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
    }
  }

  return [errorNodesTotal, warningNodes];
}

export function lint(options: LintOptions): LintRunResult {
  const cmdOptions = options.cmdOptions;
  const cancellationToken = options.cancellationToken;
  const tscCompiledProgram = options.tscCompiledProgram;
  const tsProgram = tscCompiledProgram.getProgram();

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
  const linter = new TypeScriptLinter(
    tsProgram.getTypeChecker(),
    cmdOptions.enableAutofix,
    cancellationToken,
    options.incrementalLintInfo,
    tscStrictDiagnostics,
    options.reportAutofixCb,
    options.isEtsFileCb
  );
  const { errorNodes, problemsInfos } = lintFiles(srcFiles, linter);

  consoleLog('\n\n\nFiles scanned: ', srcFiles.length);
  consoleLog('\nFiles with problems: ', errorNodes);

  const [errorNodesTotal, warningNodes] = countProblems(linter);

  logTotalProblemsInfo(errorNodesTotal, warningNodes, linter);
  logProblemsPercentageByFeatures(linter);

  return {
    errorNodes: errorNodesTotal,
    problemsInfos: mergeArrayMaps(problemsInfos, transformTscDiagnostics(tscStrictDiagnostics))
  };
}

function lintFiles(srcFiles: ts.SourceFile[], linter: TypeScriptLinter): LintRunResult {
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

function countProblemFiles(
  nodeCounters: number[],
  filesNumber: number,
  tsSrcFile: ts.SourceFile,
  fileNodes: number,
  fileErrorLines: number,
  fileWarningLines: number,
  linter: TypeScriptLinter
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
    }
  }
  if (errorNodes > 0) {
    filesNumber++;
    const errorRate = (errorNodes / fileNodes * 100).toFixed(2);
    const warningRate = (warningNodes / fileNodes * 100).toFixed(2);
    consoleLog(tsSrcFile.fileName, ': ', '\n\tError lines: ', linter.errorLineNumbersString);
    consoleLog(tsSrcFile.fileName, ': ', '\n\tWarning lines: ', linter.warningLineNumbersString);
    consoleLog(
      '\n\tError constructs (%): ',
      errorRate,
      '\t[ of ',
      fileNodes,
      ' constructs ], \t',
      fileErrorLines,
      ' lines'
    );
    consoleLog(
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

function logTotalProblemsInfo(errorNodes: number, warningNodes: number, linter: TypeScriptLinter): void {
  const errorRate = (errorNodes / linter.totalVisitedNodes * 100).toFixed(2);
  const warningRate = (warningNodes / linter.totalVisitedNodes * 100).toFixed(2);
  consoleLog('\nTotal error constructs (%): ', errorRate);
  consoleLog('\nTotal warning constructs (%): ', warningRate);
  consoleLog('\nTotal error lines:', linter.totalErrorLines, ' lines\n');
  consoleLog('\nTotal warning lines:', linter.totalWarningLines, ' lines\n');
}

function logProblemsPercentageByFeatures(linter: TypeScriptLinter): void {
  consoleLog('\nPercent by features: ');
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    const nodes = linter.nodeCounters[i];
    const lines = linter.lineCounters[i];
    const pecentage = (nodes / linter.totalVisitedNodes * 100).toFixed(2).padEnd(7, ' ');

    consoleLog(faultDesc[i].padEnd(55, ' '), pecentage, '[', nodes, ' constructs / ', lines, ' lines]');
  }
}

function shouldProcessFile(options: LintOptions, fileFsPath: string): boolean {
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
