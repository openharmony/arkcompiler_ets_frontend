/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import { Logger } from '../lib/Logger';
import { logTscDiagnostic } from '../lib/utils/functions/LogTscDiagnostic';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { Command, Option } from 'commander';
import * as ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';

const TS_EXT = '.ts';
const TSX_EXT = '.tsx';
const ETS_EXT = '.ets';

let inputFiles: string[];
let responseFile = '';
function addSrcFile(value: string): void {
  if (value.startsWith('@')) {
    responseFile = value;
  } else {
    inputFiles.push(value);
  }
}

const getFiles = (dir: string): string[] => {
  const resultFiles: string[] = [];

  const files = fs.readdirSync(dir);
  for (let i = 0; i < files.length; ++i) {
    const name = path.join(dir, files[i]);
    if (fs.statSync(name).isDirectory()) {
      resultFiles.push(...getFiles(name));
    } else {
      const extension = path.extname(name);
      if (extension === TS_EXT || extension === TSX_EXT || extension === ETS_EXT) {
        resultFiles.push(name);
      }
    }
  }

  return resultFiles;
};

function addProjectFolder(projectFolder: string, previous: string[]): string[] {
  return previous.concat([projectFolder]);
}

function formCommandLineOptions(program: Command): CommandLineOptions {
  const opts: CommandLineOptions = {
    inputFiles: inputFiles,
    warningsAsErrors: false,
    enableAutofix: false,
    arkts2: false,
    enableUseRtLogic: true
  };
  const options = program.opts();
  if (options.TSC_Errors) {
    opts.logTscErrors = true;
  }
  if (options.devecoPluginMode) {
    opts.ideMode = true;
  }
  if (options.testMode) {
    opts.testMode = true;
  }
  if (options.projectFolder) {
    doProjectFolderArg(options.projectFolder, opts);
  }
  if (options.project) {
    doProjectArg(options.project, opts);
  }
  if (options.autofix) {
    opts.enableAutofix = true;
  }
  if (options.arkts2) {
    opts.arkts2 = true;
  }
  if (options.warningsAsErrors) {
    opts.warningsAsErrors = true;
  }
  if (!options.enableUseRtLogic) {
    opts.enableUseRtLogic = false;
  }
  return opts;
}

export function parseCommandLine(commandLineArgs: string[]): CommandLineOptions {
  const program = new Command();
  program.name('tslinter').description('Linter for TypeScript sources').
    version('0.0.1');
  program.
    option('-E, --TSC_Errors', 'show error messages from Tsc').
    option('--test-mode', 'run linter as if running TS test files').
    option('--deveco-plugin-mode', 'run as IDE plugin').
    option('-p, --project <project_file>', 'path to TS project config file').
    option('--project-folder <project_folder>', 'path to folder containig TS files to verify', addProjectFolder, []).
    option('--autofix', 'automatically fix problems found by linter').
    option('--arkts-2', 'enable ArkTS 2.0 mode').
    option('--enableUseRtLogic', 'linter with RT').
    addOption(new Option('--warnings-as-errors', 'treat warnings as errors').hideHelp(true));
  program.argument('[srcFile...]', 'files to be verified', addSrcFile);

  inputFiles = [];
  // method parse() eats two first args, so make them dummy
  let cmdArgs: string[] = ['dummy', 'dummy'];
  cmdArgs.push(...commandLineArgs);
  program.parse(cmdArgs);
  if (responseFile !== '') {
    try {
      // eslint-disable-next-line no-param-reassign
      commandLineArgs = fs.
        readFileSync(responseFile.slice(1)).
        toString().
        split('\n').
        filter((e) => {
          return e.trimEnd();
        });
      cmdArgs = ['dummy', 'dummy'];
      cmdArgs.push(...commandLineArgs);
      program.parse(cmdArgs);
    } catch (error) {
      Logger.error('Failed to read response file: ' + error);
      process.exit(-1);
    }
  }

  return formCommandLineOptions(program);
}

function doProjectFolderArg(prjFolders: string[], opts: CommandLineOptions): void {
  for (let i = 0; i < prjFolders.length; i++) {
    const prjFolderPath = prjFolders[i];
    try {
      opts.inputFiles.push(...getFiles(prjFolderPath));
    } catch (error) {
      Logger.error('Failed to read folder: ' + error);
      process.exit(-1);
    }
  }
}

function doProjectArg(cfgPath: string, opts: CommandLineOptions): void {
  // Process project file (tsconfig.json) and retrieve config arguments.
  const configFile = cfgPath;

  const host: ts.ParseConfigFileHost = ts.sys as ts.System & ts.ParseConfigFileHost;

  const diagnostics: ts.Diagnostic[] = [];

  try {
    const oldUnrecoverableDiagnostic = host.onUnRecoverableConfigFileDiagnostic;
    host.onUnRecoverableConfigFileDiagnostic = (diagnostic: ts.Diagnostic): void => {
      diagnostics.push(diagnostic);
    };
    opts.parsedConfigFile = ts.getParsedCommandLineOfConfigFile(configFile, {}, host);
    host.onUnRecoverableConfigFileDiagnostic = oldUnrecoverableDiagnostic;

    if (opts.parsedConfigFile) {
      diagnostics.push(...ts.getConfigFileParsingDiagnostics(opts.parsedConfigFile));
    }

    if (diagnostics.length > 0) {
      // Log all diagnostic messages and exit program.
      Logger.error('Failed to read config file.');
      logTscDiagnostic(diagnostics, Logger.info);
      process.exit(-1);
    }
  } catch (error) {
    Logger.error('Failed to read config file: ' + error);
    process.exit(-1);
  }
}
