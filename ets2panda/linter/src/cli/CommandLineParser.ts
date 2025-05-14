/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
import { ARKTS_IGNORE_DIRS_OH_MODULES } from '../lib/utils/consts/ArktsIgnorePaths';
import type { OptionValues } from 'commander';
import { Command, Option } from 'commander';
import * as ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';

const TS_EXT = '.ts';
const TSX_EXT = '.tsx';
const ETS_EXT = '.ets';
const JS_EXT = '.js';

interface CommanderParseOptions {
  exitOnFail?: boolean;
  disableErrorOutput?: boolean;
}

interface ProcessedArguments {
  inputFiles: string[];
  responseFiles: string[];
}

interface ParsedCommand {
  opts: OptionValues;
  args: ProcessedArguments;
}

const getFiles = (dir: string): string[] => {
  const resultFiles: string[] = [];
  if (dir.includes(ARKTS_IGNORE_DIRS_OH_MODULES)) {
    return [];
  }

  const files = fs.readdirSync(dir);
  for (let i = 0; i < files.length; ++i) {
    const name = path.join(dir, files[i]);
    if (fs.statSync(name).isDirectory()) {
      resultFiles.push(...getFiles(name));
    } else {
      const extension = path.extname(name);
      if (extension === TS_EXT || extension === TSX_EXT || extension === ETS_EXT || extension === JS_EXT) {
        resultFiles.push(name);
      }
    }
  }

  return resultFiles;
};

function addProjectFolder(projectFolder: string, previous: string[]): string[] {
  return previous.concat([projectFolder]);
}

function processProgramArguments(args: string[]): ProcessedArguments {
  const processed: ProcessedArguments = {
    inputFiles: [],
    responseFiles: []
  };
  for (const arg of args) {
    if (arg.startsWith('@')) {
      processed.responseFiles.push(arg.slice(1));
    } else {
      processed.inputFiles.push(arg);
    }
  }
  return processed;
}

function parseCommand(program: Command, cmdArgs: string[]): ParsedCommand {
  program.parse(cmdArgs);
  return {
    opts: program.opts<OptionValues>(),
    args: processProgramArguments(program.args)
  };
}

function formSdkOptions(cmdOptions: CommandLineOptions, commanderOpts: OptionValues): void {
  if (commanderOpts.sdkExternalApiPath) {
    cmdOptions.sdkExternalApiPath = commanderOpts.sdkExternalApiPath;
  }
  if (commanderOpts.sdkDefaultApiPath) {
    cmdOptions.sdkDefaultApiPath = commanderOpts.sdkDefaultApiPath;
  }
  if (commanderOpts.arktsWholeProjectPath) {
    cmdOptions.arktsWholeProjectPath = commanderOpts.arktsWholeProjectPath;
  }
}

function formMigrateOptions(cmdOptions: CommandLineOptions, commanderOpts: OptionValues): void {
  if (commanderOpts.migrate) {
    cmdOptions.linterOptions.migratorMode = true;
    cmdOptions.linterOptions.enableAutofix = true;
  }
  if (commanderOpts.migrationBackupFile === false) {
    cmdOptions.linterOptions.noMigrationBackupFile = true;
  }
  if (commanderOpts.migrationMaxPass) {
    const num = Number(commanderOpts.migrationMaxPass);
    cmdOptions.linterOptions.migrationMaxPass = isNaN(num) ? 0 : num;
  }
  if (commanderOpts.migrationReport) {
    cmdOptions.linterOptions.migrationReport = true;
  }
  if (commanderOpts.arktsWholeProjectPath) {
    cmdOptions.linterOptions.wholeProjectPath = commanderOpts.arktsWholeProjectPath;
  }
}

function formCommandLineOptions(parsedCmd: ParsedCommand): CommandLineOptions {
  const opts: CommandLineOptions = {
    inputFiles: parsedCmd.args.inputFiles,
    linterOptions: {
      useRtLogic: true,
      interopCheckMode: false
    }
  };
  const options = parsedCmd.opts;
  if (options.TSC_Errors) {
    opts.logTscErrors = true;
  }
  if (options.devecoPluginMode) {
    opts.devecoPluginModeDeprecated = true;
  }
  if (options.checkTsAsSource !== undefined) {
    opts.linterOptions.checkTsAsSource = options.checkTsAsSource;
  }
  if (options.projectFolder) {
    doProjectFolderArg(options.projectFolder, opts);
  }
  if (options.project) {
    doProjectArg(options.project, opts);
  }
  if (options.autofix) {
    opts.linterOptions.enableAutofix = true;
  }
  if (options.arkts2) {
    opts.linterOptions.arkts2 = true;
  }
  if (options.warningsAsErrors) {
    opts.linterOptions.warningsAsErrors = true;
  }
  if (options.useRtLogic !== undefined) {
    opts.linterOptions.useRtLogic = options.useRtLogic;
  }
  if (options.ideInteractive) {
    opts.linterOptions.ideInteractive = true;
  }
  if (options.checkTsAndJs) {
    opts.linterOptions.checkTsAndJs = true;
  }
  if (options.homecheck) {
    opts.homecheck = true;
  }
  formSdkOptions(opts, options);
  formMigrateOptions(opts, options);
  return opts;
}

function createCommand(): Command {
  const program = new Command();
  program.
    name('tslinter').
    description('Linter for TypeScript sources').
    version('0.0.2').
    configureHelp({ helpWidth: 100 }).
    exitOverride();
  program.
    option('-E, --TSC_Errors', 'show error messages from Tsc').
    option('--check-ts-as-source', 'check TS files as source files').
    option('-p, --project <project_file>', 'path to TS project config file').
    option(
      '-f, --project-folder <project_folder>',
      'path to folder containing TS files to verify',
      addProjectFolder,
      []
    ).
    option('--autofix', 'automatically fix problems found by linter').
    option('--arkts-2', 'enable ArkTS 2.0 mode').
    option('--use-rt-logic', 'run linter with RT logic').
    option('-e, --sdk-external-api-path <paths...>', 'paths to external API files').
    option('-d, --sdk-default-api-path <path>', 'paths to default API files').
    option('--ide-interactive', 'Migration Helper IDE interactive mode').
    option('-w, --arkts-whole-project-path <path>', 'path to whole project').
    option('--migrate', 'run as ArkTS migrator').
    option('--homecheck', 'added homecheck rule validation').
    option('--no-migration-backup-file', 'Disable the backup files in migration mode').
    option('--migration-max-pass <num>', 'Maximum number of migration passes').
    option('--migration-report', 'Generate migration report').
    option('--check-ts-and-js', 'check ts and js files').
    addOption(new Option('--warnings-as-errors', 'treat warnings as errors').hideHelp(true)).
    addOption(new Option('--no-check-ts-as-source', 'check TS files as third-party libary').hideHelp(true)).
    addOption(new Option('--no-use-rt-logic', 'run linter with SDK logic').hideHelp(true)).
    addOption(new Option('--deveco-plugin-mode', 'run as IDE plugin (obsolete)').hideHelp(true));
  program.argument('[srcFile...]', 'files to be verified');
  return program;
}

export function parseCommandLine(
  commandLineArgs: string[],
  commanderParseOpts: CommanderParseOptions = {}
): CommandLineOptions {
  const { exitOnFail = true, disableErrorOutput = false } = commanderParseOpts;
  const program = createCommand();
  if (disableErrorOutput) {
    program.configureOutput({
      writeErr: () => {},
      writeOut: () => {}
    });
  }

  // method parse() eats two first args, so make them dummy
  const cmdArgs: string[] = ['dummy', 'dummy'];
  cmdArgs.push(...commandLineArgs);
  let parsedCmd: ParsedCommand;
  try {
    parsedCmd = parseCommand(program, cmdArgs);
  } catch (error) {
    if (exitOnFail) {
      process.exit(-1);
    }
    throw error;
  }
  processResponseFiles(parsedCmd);
  return formCommandLineOptions(parsedCmd);
}

function processResponseFiles(parsedCmd: ParsedCommand): void {
  if (!parsedCmd.args.responseFiles.length) {
    return;
  }
  const rspFiles = parsedCmd.args.responseFiles;
  for (const rspFile of rspFiles) {
    try {
      const rspArgs = fs.
        readFileSync(rspFile).
        toString().
        split('\n').
        filter((e) => {
          return e.trimEnd();
        });
      const cmdArgs = ['dummy', 'dummy'];
      cmdArgs.push(...rspArgs);
      const parsedRsp = parseCommand(createCommand(), cmdArgs);
      Object.assign(parsedCmd.opts, parsedRsp.opts);
      parsedCmd.args.inputFiles.push(...parsedRsp.args.inputFiles);
    } catch (error) {
      Logger.error('Failed to read response file: ' + error);
      process.exit(-1);
    }
  }
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
