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

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { lint } from '../lib/LinterRunner';
import { Logger } from '../lib/Logger';
import type { ProblemInfo } from '../lib/ProblemInfo';
import { TypeScriptLinter } from '../lib/TypeScriptLinter';
import { parseCommandLine } from './CommandLineParser';
import { compileLintOptions } from './Compiler';
import type { LinterConfig } from '../lib/LinterConfig';

export function run(): void {
  const commandLineArgs = process.argv.slice(2);
  if (commandLineArgs.length === 0) {
    Logger.info('Command line error: no arguments');
    process.exit(-1);
  }

  const cmdOptions = parseCommandLine(commandLineArgs);

  TypeScriptLinter.initGlobals();

  if (!cmdOptions.linterOptions.ideMode) {
    const compileOptions = compileLintOptions(cmdOptions);
    const result = lint(compileOptions, getEtsLoaderPath(compileOptions));
    process.exit(result.errorNodes > 0 ? 1 : 0);
  } else {
    runIDEMode(cmdOptions);
  }
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

function runIDEMode(cmdOptions: CommandLineOptions): void {
  cmdOptions.linterOptions.ideMode = true;
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
    const result = lint(compileOptions, getEtsLoaderPath(compileOptions));
    const problems = Array.from(result.problemsInfos.values());
    if (problems.length === 1) {
      showJSONMessage(problems);
    } else {
      Logger.error('Unexpected error: could not lint file');
    }
    fs.unlinkSync(tmpFileName);
  });
}

export function getEtsLoaderPath(linterConfig: LinterConfig): string | undefined {
  const tsProgram = linterConfig.tscCompiledProgram.getProgram();
  return tsProgram.getCompilerOptions().etsLoaderPath;
}
