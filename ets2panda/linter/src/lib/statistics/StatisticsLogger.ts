/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { faultsAttrs } from '../FaultAttrs';
import { Logger } from '../Logger';
import { FaultID } from '../Problems';
import { ProblemSeverity } from '../ProblemSeverity';
import type { ProblemInfo } from '../ProblemInfo';
import { faultDesc } from '../FaultDesc';
import type { FileStatistics } from './FileStatistics';
import type { FileProblemStatistics } from './FileProblemStatistics';
import type { ProjectStatistics } from './ProjectStatistics';

export function log(...args: unknown[]): void {
  let outLine = '';
  for (let k = 0; k < args.length; k++) {
    outLine += `${args[k]} `;
  }
  Logger.info(outLine);
}

function logReport(srcFileName: string, problemInfo: ProblemInfo): void {
  const faultDescr = faultDesc[problemInfo.faultId];
  const faultType = problemInfo.type;
  Logger.info(
    `Warning: ${srcFileName} (${problemInfo.line}, ${problemInfo.column}): ${faultDescr ? faultDescr : faultType}`
  );
}

function logFileProblems(fileStats: FileStatistics): void {
  for (const problem of fileStats.problems) {
    logReport(fileStats.srcFileName, problem);
  }
}

function countProblemStats(fileStats: FileStatistics): FileProblemStatistics {
  let errors = 0;
  let warnings = 0;
  const errorLines = new Set<number>();
  const warningLines = new Set<number>();
  fileStats.problems.forEach((problemInfo: ProblemInfo) => {
    const line = problemInfo.line;
    switch (faultsAttrs[problemInfo.faultId].severity) {
      case ProblemSeverity.ERROR: {
        errors++;
        errorLines.add(line);
        break;
      }
      case ProblemSeverity.WARNING: {
        warnings++;
        warningLines.add(line);
        break;
      }
      default:
    }
  });
  const sortFunc = (a, b): number => {
    return a - b;
  };
  let errorLineNumbersString = '';
  Array.from(errorLines).
    sort(sortFunc).
    forEach((line) => {
      errorLineNumbersString += line + ', ';
    });
  let warningLineNumbersString = '';
  Array.from(warningLines).
    sort(sortFunc).
    forEach((line) => {
      warningLineNumbersString += line + ', ';
    });
  return {
    errors,
    warnings,
    errorLines: errorLines.size,
    warningLines: warningLines.size,
    errorLineNumbersString,
    warningLineNumbersString
  };
}

function logProblemFileInfo(fileStats: FileStatistics, problemStats: FileProblemStatistics): void {
  if (problemStats.errors > 0) {
    const errorRate = (problemStats.errors / fileStats.visitedNodes * 100).toFixed(2);
    const warningRate = (problemStats.warnings / fileStats.visitedNodes * 100).toFixed(2);
    log(fileStats.srcFileName, ': ', '\n\tError lines: ', problemStats.errorLineNumbersString);
    log(fileStats.srcFileName, ': ', '\n\tWarning lines: ', problemStats.warningLineNumbersString);
    log(
      '\n\tError constructs (%): ',
      errorRate,
      '\t[ of ',
      fileStats.visitedNodes,
      ' constructs ], \t',
      problemStats.errorLines,
      ' lines'
    );
    log(
      '\n\tWarning constructs (%): ',
      warningRate,
      '\t[ of ',
      fileStats.visitedNodes,
      ' constructs ], \t',
      problemStats.warningLines,
      ' lines'
    );
  }
}

function logTotalProblemsInfo(
  totalErrors: number,
  totalWarnings: number,
  totalErrorLines: number,
  totalWarningLines: number,
  totalVisitedNodes: number
): void {
  const errorRate = (totalErrors / totalVisitedNodes * 100).toFixed(2);
  const warningRate = (totalWarnings / totalVisitedNodes * 100).toFixed(2);
  log('\nTotal error constructs (%): ', errorRate);
  log('\nTotal warning constructs (%): ', warningRate);
  log('\nTotal error lines:', totalErrorLines, ' lines\n');
  log('\nTotal warning lines:', totalWarningLines, ' lines\n');
}

function logProblemsPercentageByFeatures(projectStats: ProjectStatistics, totalVisitedNodes: number): void {
  log('\nPercent by features: ');
  for (let i = 0; i < FaultID.LAST_ID; i++) {
    let nodes = 0;
    let lines = 0;
    for (const fileStats of projectStats.fileStats) {
      nodes += fileStats.nodeCounters[i];
      lines += fileStats.lineCounters[i].size;
    }
    const pecentage = (nodes / totalVisitedNodes * 100).toFixed(2).padEnd(7, ' ');
    log(faultDesc[i].padEnd(55, ' '), pecentage, '[', nodes, ' constructs / ', lines, ' lines]');
  }
}

export function logStatistics(projectStats: ProjectStatistics): void {
  let filesWithErrors = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  let totalErrorLines = 0;
  let totalWarningLines = 0;
  let totalVisitedNodes = 0;

  for (const fileStats of projectStats.fileStats) {
    logFileProblems(fileStats);

    const problemStats = countProblemStats(fileStats);
    logProblemFileInfo(fileStats, problemStats);

    if (problemStats.errors > 0) {
      filesWithErrors++;
    }

    totalErrors += problemStats.errors;
    totalWarnings += problemStats.warnings;
    totalErrorLines += problemStats.errorLines;
    totalWarningLines += problemStats.warningLines;
    totalVisitedNodes += fileStats.visitedNodes;
  }

  log('\n\n\nFiles scanned: ', projectStats.fileStats.length);
  log('\nFiles with problems: ', filesWithErrors);

  logTotalProblemsInfo(totalErrors, totalWarnings, totalErrorLines, totalWarningLines, totalVisitedNodes);
  logProblemsPercentageByFeatures(projectStats, totalVisitedNodes);
}
