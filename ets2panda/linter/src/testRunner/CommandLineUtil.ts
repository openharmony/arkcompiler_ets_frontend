/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import { execSync, spawnSync } from 'node:child_process';
import { platform } from 'node:process';
import * as path from 'node:path';

const NODEJS_PROGRAM = 'node';
const SHELL_PROGRAM = '/bin/sh';
const NODEJS_PRINT_CMD_LINE_ARGS_SCRIPT = 'print_cmd_line_args.js';
const BATCH_PRINT_CMD_LINE_ARGS_SCRIPT = 'print_cmd_line_args.bat';
const SHELL_PRINT_CMD_LINE_ARGS_SCRIPT = 'print_cmd_line_args.sh';

export function getCommandLineArguments(cmdLine: string): string[] {

  /*
   * Note: The platform-specific scripts generally run faster than a NodeJS script,
   * so use it when possible to increase the overall performance.
   */
  let output = '';
  switch (platform) {
    case 'win32':
      output = windows(cmdLine);
      break;
    case 'linux':
    case 'cygwin':
      output = linux(cmdLine);
      break;
    default:
      output = nodeJs(cmdLine);
  }
  return JSON.parse(output).args;
}

function getScriptModulePath(script: string): string {
  return path.resolve(__dirname, script);
}

function spawnSyncStdout(command: string): string {
  return spawnSync(command, { shell: true, encoding: 'utf8' }).stdout;
}

function execSyncStdout(command: string): string {
  return execSync(command, { encoding: 'utf-8' });
}

function nodeJs(cmdArgs: string): string {
  return spawnSyncStdout(`${NODEJS_PROGRAM} ${getScriptModulePath(NODEJS_PRINT_CMD_LINE_ARGS_SCRIPT)} ${cmdArgs}`);
}

function windows(cmdArgs: string): string {
  return spawnSyncStdout(`${getScriptModulePath(BATCH_PRINT_CMD_LINE_ARGS_SCRIPT)} ${cmdArgs}`);
}

function linux(cmdArgs: string): string {
  return execSyncStdout(`${SHELL_PROGRAM} ${getScriptModulePath(SHELL_PRINT_CMD_LINE_ARGS_SCRIPT)} ${cmdArgs}`);
}
