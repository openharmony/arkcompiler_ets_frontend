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
import { ProblemInfo } from './ProblemInfo';
import { TypeScriptLinter, consoleLog } from './TypeScriptLinter';
import { FaultID } from './Problems';
import { faultDesc } from './FaultDesc';
import { faultsAttrs } from './FaultAttrs';
import { LintRunResult } from './LintRunResult';
import * as path from 'node:path';
import { compile } from './CompilerWrapper';
import { LintOptions } from './LintOptions';
import { AutofixInfoSet } from './Autofixer';
import { TSCCompiledProgram, TSCCompiledProgramSimple, TSCCompiledProgramWithDiagnostics, getStrictOptions } from './ts-diagnostics/TSCCompiledProgram';
import { mergeArrayMaps } from './utils/functions/MergeArrayMaps';
import { getTscDiagnostics } from './ts-diagnostics/GetTscDiagnostics';
import { transformTscDiagnostics } from './ts-diagnostics/TransformTscDiagnostics';
import { ARKTS_IGNORE_DIRS, ARKTS_IGNORE_FILES } from './utils/consts/ArktsIgnorePaths';
import { pathContainsDirectory } from './utils/functions/PathHelper';

export function lint(options: LintOptions): LintRunResult {
  const cmdOptions = options.cmdOptions;
  const cancellationToken = options.cancellationToken;

  const tscDiagnosticsLinter = createLinter(options);
  const tsProgram = tscDiagnosticsLinter.getOriginalProgram();

  // Prepare list of input files for linter and retrieve AST for those files.
  let inputFiles: string[] = cmdOptions.inputFiles;
  if (cmdOptions.parsedConfigFile) {
    inputFiles = cmdOptions.parsedConfigFile.fileNames;
    if (cmdOptions.inputFiles.length > 0) {
      // Apply linter only to the project source files that are specified
      // as a command-line arguments. Other source files will be discarded.
      const cmdInputsResolvedPaths = cmdOptions.inputFiles.map((x) => path.resolve(x));
      const configInputsResolvedPaths = inputFiles.map((x) => path.resolve(x));
      inputFiles = configInputsResolvedPaths.filter((x) => cmdInputsResolvedPaths.some((y) => x === y));
    }
  }

  // #13436: ignore-list for ArkTS projects.
  inputFiles = inputFiles.filter(input =>
    !ARKTS_IGNORE_FILES.some(ignore => path.basename(input) === ignore) &&
    !ARKTS_IGNORE_DIRS.some(ignore => pathContainsDirectory(path.resolve(input), ignore)));

  const srcFiles: ts.SourceFile[] = [];
  for (const inputFile of inputFiles) {
    const srcFile = tsProgram.getSourceFile(inputFile);
    if (srcFile) srcFiles.push(srcFile);
  }

  const tscStrictDiagnostics = getTscDiagnostics(tscDiagnosticsLinter, srcFiles);

  const linter = new TypeScriptLinter(
    tsProgram.getTypeChecker(),
    new AutofixInfoSet(cmdOptions.autofixInfo),
    !!cmdOptions.strictMode,
    cmdOptions.warningsAsErrors,
    cancellationToken,
    options.incrementalLintInfo,
    tscStrictDiagnostics,
    options.reportAutofixCb
  );
  const { errorNodes, problemsInfos } = lintFiles(srcFiles, linter);

  consoleLog('\n\n\nFiles scanned: ', srcFiles.length);
  consoleLog('\nFiles with problems: ', errorNodes);

  let errorNodesTotal = 0, warningNodes = 0;
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    // if Strict mode - count all cases
    if (!linter.strictMode && faultsAttrs[i].migratable) // In relax mode skip migratable
      continue;

    if (faultsAttrs[i].warning) warningNodes += linter.nodeCounters[i];
    else errorNodesTotal += linter.nodeCounters[i];
  }
  logTotalProblemsInfo(errorNodesTotal, warningNodes, linter);
  logProblemsPercentageByFeatures(linter);
  return {
    errorNodes: errorNodesTotal,
    problemsInfos: mergeArrayMaps(problemsInfos, transformTscDiagnostics(tscStrictDiagnostics)),
  };
}

export function createLinter(options: LintOptions): TSCCompiledProgram {
  if (options.tscDiagnosticsLinter) {
    return options.tscDiagnosticsLinter;
  }
  const tsProgram = options.tsProgram ?? compile(options, getStrictOptions());
  if (options.realtimeLint) {
    return new TSCCompiledProgramSimple(tsProgram);
  }
  return new TSCCompiledProgramWithDiagnostics(tsProgram, options);
}

function lintFiles(srcFiles: ts.SourceFile[], linter: TypeScriptLinter): LintRunResult {
  let problemFiles = 0;
  let problemsInfos: Map<string, ProblemInfo[]> = new Map();

  for (const srcFile of srcFiles) {
    const prevVisitedNodes = linter.totalVisitedNodes;
    const prevErrorLines = linter.totalErrorLines;
    const prevWarningLines = linter.totalWarningLines;
    linter.errorLineNumbersString = '';
    linter.warningLineNumbersString = '';
    const nodeCounters: number[] = [];

    for (let i = 0; i < FaultID.LAST_ID; i++)
      nodeCounters[i] = linter.nodeCounters[i];

    linter.lint(srcFile);
    // save results and clear problems array
    problemsInfos.set( path.normalize(srcFile.fileName), [...linter.problemsInfos]);
    linter.problemsInfos.length = 0;

    // print results for current file
    const fileVisitedNodes = linter.totalVisitedNodes - prevVisitedNodes;
    const fileErrorLines = linter.totalErrorLines - prevErrorLines;
    const fileWarningLines = linter.totalWarningLines - prevWarningLines;

    problemFiles = countProblemFiles(
      nodeCounters, problemFiles, srcFile, fileVisitedNodes, fileErrorLines, fileWarningLines, linter
    );
  }

  return {
    errorNodes: problemFiles,
    problemsInfos: problemsInfos,
  };
}

function countProblemFiles(
  nodeCounters: number[], filesNumber: number, tsSrcFile: ts.SourceFile, 
  fileNodes: number, fileErrorLines: number, fileWarningLines: number, linter: TypeScriptLinter,
) {
  let errorNodes = 0, warningNodes = 0;
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    let nodeCounterDiff = linter.nodeCounters[i] - nodeCounters[i];
    if (faultsAttrs[i].warning) warningNodes += nodeCounterDiff;
    else errorNodes += nodeCounterDiff;
  }

  if (errorNodes > 0) {
    filesNumber++;
    let errorRate = ((errorNodes / fileNodes) * 100).toFixed(2);
    let warningRate = ((warningNodes / fileNodes) * 100).toFixed(2);
    consoleLog(tsSrcFile.fileName, ': ', '\n\tError lines: ', linter.errorLineNumbersString);
    consoleLog(tsSrcFile.fileName, ': ', '\n\tWarning lines: ', linter.warningLineNumbersString);
    consoleLog('\n\tError constructs (%): ', errorRate, '\t[ of ', fileNodes, ' constructs ], \t', fileErrorLines, ' lines');
    consoleLog('\n\tWarning constructs (%): ', warningRate, '\t[ of ', fileNodes, ' constructs ], \t', fileWarningLines, ' lines');
  }

  return filesNumber;
}

function logTotalProblemsInfo(errorNodes: number, warningNodes: number, linter: TypeScriptLinter) {
  let errorRate = ((errorNodes / linter.totalVisitedNodes) * 100).toFixed(2);
  let warningRate = ((warningNodes / linter.totalVisitedNodes) * 100).toFixed(2);
  consoleLog('\nTotal error constructs (%): ', errorRate);
  consoleLog('\nTotal warning constructs (%): ', warningRate);
  consoleLog('\nTotal error lines:', linter.totalErrorLines, ' lines\n');
  consoleLog('\nTotal warning lines:', linter.totalWarningLines, ' lines\n');
}

function logProblemsPercentageByFeatures(linter: TypeScriptLinter) {
  consoleLog('\nPercent by features: ');
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    // if Strict mode - count all cases
    if (!linter.strictMode && faultsAttrs[i].migratable)
      continue;
    
    let nodes = linter.nodeCounters[i];
    let lines = linter.lineCounters[i];
    let pecentage = ((nodes / linter.totalVisitedNodes) * 100).toFixed(2).padEnd(7, ' ');

    consoleLog(faultDesc[i].padEnd(55, ' '), pecentage, '[', nodes, ' constructs / ', lines, ' lines]');
  }
}
