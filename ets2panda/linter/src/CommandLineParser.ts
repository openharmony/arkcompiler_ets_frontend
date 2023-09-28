/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import Logger from '../utils/logger';
import { logTscDiagnostic } from './utils/functions/LogTscDiagnostic';
import { decodeAutofixInfo } from './utils/functions/LinterInfo';
import { CommandLineOptions } from './CommandLineOptions';
import { AUTOFIX_ALL } from './Autofixer';
import { Command, Option } from 'commander';
import * as ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';

const TS_EXT = '.ts';
const TSX_EXT = '.tsx';
const ETS_EXT = '.ets';
const JSON_EXT = '.json';

const logger = Logger.getLogger();

let inputFiles: string[];
let responseFile = '';
function addSrcFile(value: string, dummy: string) {
  if(value.startsWith('@'))
    responseFile = value;
  else
    inputFiles.push(value);
}

const getFiles = (dir: string): string[] => {
  const resultFiles: string[] = [];

  const files = fs.readdirSync(dir);
  for (let i = 0; i < files.length; ++i) {
    let name = path.join(dir, files[i]);
    if (fs.statSync(name).isDirectory()) {
      resultFiles.push(...getFiles(name));
    } else {
      let extension = path.extname(name);
      if (extension === TS_EXT || extension === TSX_EXT || extension === ETS_EXT)
        resultFiles.push(name);
    }
  }

  return resultFiles;
};

function addProjectFolder(projectFolder: string, previous: any ) {
  return previous.concat([projectFolder]);
}

export function parseCommandLine(commandLineArgs: string[]): CommandLineOptions {
  const opts: CommandLineOptions = { inputFiles: [], warningsAsErrors: false };

  const program = new Command();
  program
    .name('tslinter')
    .description('Linter for TypeScript sources')
    .version('0.0.1');
  program
    .option('-E, --TSC_Errors', 'show error messages from Tsc')
    .option('--relax', 'relax mode On')
    .option('--test-mode', 'run linter as if running TS test files')
    .option('--deveco-plugin-mode', 'run as IDE plugin')
    .option('-p, --project <project_file>', 'path to TS project config file')
    .option('--project-folder <project_folder>', 'path to folder containig TS files to verify', addProjectFolder, [])
    .option('--autofix [autofix.json]', 'fix errors specified by JSON file (all if file is omitted)',
      (val: string, prev: string|boolean) => { return val.endsWith(JSON_EXT) ? val : true; })
    .addOption(new Option('--warnings-as-errors', 'treat warnings as errors').hideHelp(true));
  program
    .argument('[srcFile...]', 'files to be verified', addSrcFile);

  opts.strictMode = true; // Default mode of the linter.
  inputFiles = [];
  let cmdArgs: string[] = ['dummy', 'dummy']; // method parse() eats two first args, so make them dummy
  cmdArgs.push(...commandLineArgs);
  program.parse(cmdArgs);
  if (responseFile !== '') {
    try {
      commandLineArgs = fs.readFileSync(responseFile.slice(1)).toString().split('\n').filter((e) => e.trimEnd());
      cmdArgs = ['dummy', 'dummy'];
      cmdArgs.push(...commandLineArgs);
      program.parse( cmdArgs);
    } catch (error: any) {
      logger.error('Failed to read response file: ' + (error.message ?? error));
      process.exit(-1)
    }
  }
  opts.inputFiles = inputFiles;

  const options = program.opts();
  if (options.relax) opts.strictMode = false;
  if (options.TSC_Errors) opts.logTscErrors = true;
  if (options.devecoPluginMode) opts.ideMode = true;
  if (options.testMode) opts.testMode = true;
  if (options.projectFolder) doProjectFolderArg(options.projectFolder, opts); 
  if (options.project) doProjectArg(options.project, opts);
  if (options.autofix) doAutofixArg(options.autofix, opts);
  if (options.warningsAsErrors) opts.warningsAsErrors = true;
  return opts;
}

function doProjectFolderArg(prjFolders: string[], opts: CommandLineOptions) {
  for( let i = 0; i < prjFolders.length; i++ ) {
    var prjFolderPath = prjFolders[ i ];
    try {
      opts.inputFiles.push(...getFiles(prjFolderPath));
    } catch (error: any) {
      logger.error('Failed to read folder: ' + (error.message ?? error));
      process.exit(-1);
    }
  }
}

function doProjectArg(cfgPath: string, opts: CommandLineOptions) {
  // Process project file (tsconfig.json) and retrieve config arguments.
  const configFile = cfgPath;

  const host: ts.ParseConfigFileHost = ts.sys as ts.System & ts.ParseConfigFileHost;

  const diagnostics: ts.Diagnostic[] = [];

  try {
    const oldUnrecoverableDiagnostic = host.onUnRecoverableConfigFileDiagnostic;
    host.onUnRecoverableConfigFileDiagnostic = (diagnostic: ts.Diagnostic) => { diagnostics.push(diagnostic); };
    opts.parsedConfigFile = ts.getParsedCommandLineOfConfigFile(configFile, {}, host);
    host.onUnRecoverableConfigFileDiagnostic = oldUnrecoverableDiagnostic;

    if (opts.parsedConfigFile)
      diagnostics.push(...ts.getConfigFileParsingDiagnostics(opts.parsedConfigFile));

    if (diagnostics.length > 0) {
      // Log all diagnostic messages and exit program.
      logger.error('Failed to read config file.');
      logTscDiagnostic(diagnostics, logger.info);
      process.exit(-1);
    }
  } catch (error: any) {
    logger.error('Failed to read config file: ' + (error.message ?? error));
    process.exit(-1);
  }
}

function doAutofixArg(autofixOptVal: string|boolean, opts: CommandLineOptions) {
  if (typeof autofixOptVal === 'string') {
    let autofixInfoStr = fs.readFileSync(autofixOptVal).toString();
    let autofixInfos = JSON.parse(autofixInfoStr);
    opts.autofixInfo = autofixInfos.autofixInfo.map((x: string) => decodeAutofixInfo(x));
  }
  else opts.autofixInfo = [AUTOFIX_ALL];
}
