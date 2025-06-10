/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { lint } from '../lib/LinterRunner';
import { Logger } from '../lib/Logger';
import type { ProblemInfo } from '../lib/ProblemInfo';
import { parseCommandLine } from './CommandLineParser';
import { compileLintOptions, getEtsLoaderPath } from '../lib/ts-compiler/Compiler';
import { logStatistics } from '../lib/statistics/StatisticsLogger';
import { arkts2Rules } from '../lib/utils/consts/ArkTS2Rules';

export function run(): void {
  const commandLineArgs = process.argv.slice(2);
  if (commandLineArgs.length === 0) {
    Logger.info('Command line error: no arguments');
    process.exit(-1);
  }

  const cmdOptions = parseCommandLine(commandLineArgs);

  if (cmdOptions.devecoPluginModeDeprecated) {
    runIdeModeDeprecated(cmdOptions);
  } else if (cmdOptions.linterOptions.ideInteractive) {
    runIdeInteractiveMode(cmdOptions);
  } else {
    const compileOptions = compileLintOptions(cmdOptions);
    const result = lint(compileOptions);
    logStatistics(result.projectStats);
    process.exit(result.hasErrors ? 1 : 0);
  }
}

async function runIdeInteractiveMode(cmdOptions: CommandLineOptions): Promise<void> {
  cmdOptions.followSdkSettings = true;
  cmdOptions.disableStrictDiagnostics = true;
  const compileOptions = compileLintOptions(cmdOptions);
  let homeCheckResult = new Map<string, ProblemInfo[]>();
  const mergedProblems = new Map<string, ProblemInfo[]>();
  
  const result = lint(compileOptions, getEtsLoaderPath(compileOptions), homeCheckResult);

  for (const [filePath, problems] of result.problemsInfos) {
    if (!mergedProblems.has(filePath)) {
      mergedProblems.set(filePath, []);
    }
    let filteredProblems = problems;
    if (cmdOptions.linterOptions.arkts2) {
      filteredProblems = problems.filter((problem) => {
        return arkts2Rules.includes(problem.ruleTag);
      });
    }
    mergedProblems.get(filePath)!.push(...filteredProblems);
  }
  const reportData = Object.fromEntries(mergedProblems);
  await generateReportFile(reportData);

  for (const [filePath, problems] of mergedProblems) {
    const reportLine = JSON.stringify({ filePath, problems }) + '\n';
    await processSyncOut(reportLine);
  }
  await processSyncErr('{"content":"report finish","messageType":1,"indictor":1}\n');
  process.exit(0);
}

async function generateReportFile(reportData): Promise<void> {
  const reportFilePath = path.join('scan-report.json');
  try {
    await fs.promises.writeFile(reportFilePath, JSON.stringify(reportData, null, 2));
  } catch (error) {
    console.error('Error generating report file:', error);
  }
}

async function processSyncOut(message: string): Promise<void> {
  await new Promise((resolve) => {
    process.stdout.write(message, () => {
      resolve('success');
    });
  });
}

async function processSyncErr(message: string): Promise<void> {
  await new Promise((resolve) => {
    process.stderr.write(message, () => {
      resolve('success');
    });
  });
}

function getTempFileName(): string {
  return path.join(os.tmpdir(), Math.floor(Math.random() * 10000000).toString() + '_linter_tmp_file.ts');
}

function showJSONMessage(problems: ProblemInfo[][]): void {
  const jsonMessage = problems[0].map((x) => {
    return {
      line: x.line,
      column: x.column,
      start: x.start,
      end: x.end,
      type: x.type,
      suggest: x.suggest,
      rule: x.rule,
      severity: x.severity,
      autofix: x.autofix
    };
  });
  Logger.info(`{"linter messages":${JSON.stringify(jsonMessage)}}`);
}

function runIdeModeDeprecated(cmdOptions: CommandLineOptions): void {
  const tmpFileName = getTempFileName();
  // read data from stdin
  const writeStream = fs.createWriteStream(tmpFileName, { flags: 'w' });
  const rl = readline.createInterface({
    input: process.stdin,
    output: writeStream,
    terminal: false
  });

  rl.on('line', (line: string) => {
    fs.appendFileSync(tmpFileName, line + '\n');
  });
  rl.once('close', () => {
    // end of input
    writeStream.close();
    cmdOptions.inputFiles = [tmpFileName];
    if (cmdOptions.parsedConfigFile) {
      cmdOptions.parsedConfigFile.fileNames.push(tmpFileName);
    }
    const compileOptions = compileLintOptions(cmdOptions);
    const result = lint(compileOptions);
    const problems = Array.from(result.problemsInfos.values());
    if (problems.length === 1) {
      showJSONMessage(problems);
    } else {
      Logger.error('Unexpected error: could not lint file');
    }
    fs.unlinkSync(tmpFileName);
  });
}
