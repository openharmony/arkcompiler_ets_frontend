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

import * as ts from "typescript";
import * as fs from "node:fs";

const TS_EXT = ".ts";
const TSX_EXT = ".tsx";

export interface CommandLineOptions {
    Strict_Mode?: boolean;
    IDE_Mode?: boolean;
    TSC_Errors?: boolean;
    ParsedConfigFile?: ts.ParsedCommandLine;
    InputFiles: string[];
}

var getFiles = (dir: string): string[] => {
    let resultFiles: string[] = [];

    var files = fs.readdirSync(dir);
    for (var i in files){
        var name = dir + '/' + files[i];
        if (fs.statSync(name).isDirectory()) {
            resultFiles.push(...getFiles(name));
        } else {
            name = name.trimEnd();
            if(name.endsWith(TS_EXT) || name.endsWith(TSX_EXT))
                resultFiles.push(name);
        }
    }

    return resultFiles;
};

export function parseCommandLine(commandLineArgs: string[]): CommandLineOptions {
    let opts: CommandLineOptions = { InputFiles: [] };

    let argc = 0;
    while (argc < commandLineArgs.length) {
        let arg = commandLineArgs[argc];

        if (arg[0] === '@') {
            // Process arguments from the specified response file. Any following
            // argument on the command-line will be ignored.
            // Note: The 'filter(e => e)' call is used to remove empty strings
            // from parsed argument list.
            try {
                commandLineArgs = fs.readFileSync(arg.slice(1)).toString().split("\n").filter(e => e.trimEnd());
                argc = 0;
                continue;
            } catch (error: any) {
                console.error("Failed to read response file: " + (error.message ?? error));
            }
        }
        else if(arg === "--project-folder") {
            ++argc;
            if (argc >= commandLineArgs.length) {
                console.log("Command line error: no argument for option:", arg);
                process.exit(-1);
            }

            try {
                opts.InputFiles.push(...getFiles(commandLineArgs[argc]));
            } catch (error: any) {
                console.error("Failed to read folder: " + (error.message ?? error));
                process.exit(-1);
            }
        }
        else if (arg === "--strict") {
            opts.Strict_Mode = true;
        }
        else if (arg ==="-E" || arg ==="--TSC_Errors") {
            opts.TSC_Errors = true;
        }
        else if (arg === "--deveco-plugin-mode") {
            opts.IDE_Mode = true;
        }
        else if (arg === "-p" || arg === "--project") {
            ++argc;
            if (argc >= commandLineArgs.length) {
                console.log("Command line error: no argument for option:", arg);
                process.exit(-1);
            }

            // Process project file (tsconfig.json) and retrieve config arguments.
            let configFile = commandLineArgs[argc];

            let host: ts.ParseConfigFileHost = ts.sys as any;
            let diagnostics: ts.Diagnostic[] = [];

            try {
                host.onUnRecoverableConfigFileDiagnostic = (diagnostic: ts.Diagnostic) => { diagnostics.push(diagnostic); };
                opts.ParsedConfigFile = ts.getParsedCommandLineOfConfigFile(configFile, {}, host);
                host.onUnRecoverableConfigFileDiagnostic = undefined;
                
                diagnostics.push(...ts.getConfigFileParsingDiagnostics(opts.ParsedConfigFile));
                if (diagnostics.length > 0) {
                    // Log all diagnostic messages and exit program.
                    console.log("Failed to read config file.");
                    diagnostics.forEach(diagnostic => {
                        if (diagnostic.file) {
                            let { line, character } = ts.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start!);
                            let message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
                            console.log(`${diagnostic.file.fileName} (${line + 1},${character + 1}): ${message}`);
                        } else {
                            console.log(ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));
                        }
                    });
                    process.exit(-1);
                }
            } catch (error: any) {
                console.error("Failed to read config file: " + (error.message ?? error));
                process.exit(-1);
            }
        }
        else {
            opts.InputFiles.push(arg);
        }
        argc++;
    }

    return opts;
}