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

import * as ts from "typescript";
import { TypeScriptLinter } from "./TypeScriptLinter";
import { NodeType } from "./Problems";
import { parseCommandLine, CommandLineOptions } from "./CommandLineParser";
import * as fs from "node:fs";
import * as os from "node:os";
import * as readline from "node:readline";
import * as path from "node:path"

const BAD_SYNTAX_NUM = NodeType.LAST_NODE_TYPE;

const { pipeline } = require('node:stream');

function console_log(...data: string[] | any []) {
    if(TypeScriptLinter.IDE_mode)
        return;

    let k = 0;
    let outLine = '';
    while(k < data.length) {
        outLine += `${data[k]}`;
        k++
    }

    console.log(outLine)
}

function compile(createProgramOptions: ts.CreateProgramOptions): ts.Program {
    let program = ts.createProgram(createProgramOptions);

    // Log Tsc errors if needed
    if(TypeScriptLinter.TSC_Errors) {
        let diagnostics = ts.getPreEmitDiagnostics(program);
        diagnostics.forEach(diagnostic => {
            if (diagnostic.file) {
                let { line, character } = ts.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start!);
                let message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
                console_log(`${diagnostic.file.fileName} (${line + 1},${character + 1}): ${message}`);
            } else {
                console_log(ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));
            }
        });
    }
    
    return program;
}

export function lint(cmdOptions: CommandLineOptions): number {
    TypeScriptLinter.STRICT_mode = !!cmdOptions.Strict_Mode;
    TypeScriptLinter.TSC_Errors = !!cmdOptions.TSC_Errors;

    let tsProgramOptions: ts.CreateProgramOptions;
    if (cmdOptions.ParsedConfigFile) {
        tsProgramOptions = {
            rootNames: cmdOptions.ParsedConfigFile.fileNames,
            options: cmdOptions.ParsedConfigFile.options,
            projectReferences: cmdOptions.ParsedConfigFile.projectReferences,
            configFileParsingDiagnostics: ts.getConfigFileParsingDiagnostics(cmdOptions.ParsedConfigFile)
        };
    } else {
        tsProgramOptions = {
            rootNames: cmdOptions.InputFiles,
            options: {
                target: ts.ScriptTarget.Latest,
                module: ts.ModuleKind.CommonJS
            }
        };
    }
    const tsProgram = compile(tsProgramOptions);
    
    // Prepare list of input files for linter and retrieve AST for those files.
    let linterInputFiles: string[];
    if (cmdOptions.ParsedConfigFile) {
        linterInputFiles = cmdOptions.ParsedConfigFile.fileNames;

        if (cmdOptions.InputFiles.length > 0) {
            // Apply linter only to the project source files that are specified
            // as a command-line arguments. Other source files will be discarded.
            let cmdInputsResolvedPaths = cmdOptions.InputFiles.map(x => path.resolve(x));
            let configInputsResolvedPaths = linterInputFiles.map(x => path.resolve(x));
            linterInputFiles = configInputsResolvedPaths.filter(x => cmdInputsResolvedPaths.some(y => x === y));
        }
    }
    else {
        linterInputFiles = cmdOptions.InputFiles;
    }

    let tsSrcFiles = linterInputFiles.map((val, idx, array) => tsProgram.getSourceFile(val));

    let problemFileCounter = 0;
    console_log("\n\n\n");
    for (let tsSrcFile of tsSrcFiles) {
        let currentNodes = TypeScriptLinter.nodeCntr;
        let currentLines = TypeScriptLinter.commonLineCounter;
        TypeScriptLinter.lineNumbersString = "";
        TypeScriptLinter.lineNumbersStringPosCntr = 0;
        TypeScriptLinter.specificNodeLineNumbers = "";
        TypeScriptLinter.specificNodeLineNumbersPosCntr = 0;
        let nodeCounters: number[] = [ 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0 ];
        let lineCounters: number[] = [ 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0 ];

        for (let i = 0 ; i < BAD_SYNTAX_NUM; i++) {
            nodeCounters[i] = TypeScriptLinter.nodeCounters[i];
            lineCounters[i] = TypeScriptLinter.lineCounters[i];
        }

        let linter = new TypeScriptLinter(tsSrcFile, tsProgram);

        linter.lint();

        // print results for current file
        let currentFileNodes = TypeScriptLinter.nodeCntr - currentNodes;
        let currentFileLines = TypeScriptLinter.commonLineCounter - currentLines;

        let badNodes = 0;
        let badLines = 0;
        for (let i = 0 ; i< BAD_SYNTAX_NUM; i++) {
            badNodes += TypeScriptLinter.nodeCounters[i] - nodeCounters[i];
            badLines += TypeScriptLinter.lineCounters[i] - lineCounters[i];
        }

        if (badNodes > 0) {
            problemFileCounter++;
            console_log( tsSrcFile.fileName, ": ",
                            "\n\tProblem lines: ", TypeScriptLinter.lineNumbersString,
                            "\n\tuntranslated nodes (%): ",
                            (badNodes / currentFileNodes * 100).toFixed(2),
                            "\t[ of ", currentFileNodes, " nodes ], \t",
                            currentFileLines, " lines");
            console_log("\tUnion types at lines: ", TypeScriptLinter.specificNodeLineNumbers,"\n")
        }

        // Printing of the used decorator is a temporary functionality. It's just to collec statistic of used decorator types.
        if (linter.decorators.size) {
            console_log("Used decorators:");
            linter.decorators.forEach((v: number, key: String) => { console_log("\t", key, "\t\t", v); });
        }
        else
            console_log("No decorators used.");

        //let xmlString = stsCompUnit.toXML();
        //let xmlFile = tsSrcFile.fileName + ".xml";
        //writeFileSync(xmlFile, xmlString);
    }

    console_log("\nFiles scanned: ", tsSrcFiles.length, " . Files with untranslatable syntax: ", problemFileCounter);

    let badNodes = 0;
    let sumLines = 0;
    for (let i = 0 ; i < BAD_SYNTAX_NUM; i++) {
        // if Strict mode - count all cases
        if (TypeScriptLinter.STRICT_mode || TypeScriptLinter.printInRelaxModeFlags[i]) {
            badNodes += TypeScriptLinter.nodeCounters[i];
            sumLines += TypeScriptLinter.lineCounters[i];
        }
    }

    console_log("\nTotal untranslateble nodes (%): ",
                                      (badNodes / TypeScriptLinter.nodeCntr * 100).toFixed(2),
                                      "\t[ of ", TypeScriptLinter.nodeCntr, " nodes ], \t",
                                      TypeScriptLinter.commonLineCounter, " lines\n")

    console_log("\nPercent by features: ");

    for (let i = 0 ; i< BAD_SYNTAX_NUM; i++) {
        // if Strict mode - count all cases
        if (!TypeScriptLinter.STRICT_mode && !TypeScriptLinter.printInRelaxModeFlags[i])
            continue;

        console_log(TypeScriptLinter.nodeDescription[i],
                (TypeScriptLinter.nodeCounters[i] / TypeScriptLinter.nodeCntr * 100).toFixed(2),
                                 "\t[",TypeScriptLinter.nodeCounters[i],
                                  " nodes / ",TypeScriptLinter.lineCounters[i],
                                  " lines]" );

        // Commenting this out, as it's not a problem any more but a part of STS language.
        // if( i === NodeType.UnionType ) {
        //     console_log( "\t\t\t union nodes of kind T | null :  ", TypeScriptLinter.unionTNull);
        //     console_log( "\t\t\t union nodes of kind T | any :  ", TypeScriptLinter.unionTAny);
        //     console_log( "\t\t\t union nodes of kind T | undefined :  ", TypeScriptLinter.unionTUndefined);
        // }

        if( i === NodeType.ObjectLiteralNoContextType ) {
            console_log( "\t\t\t object literal nodes which are not function parameters :  ", TypeScriptLinter.objLiteralNotParameter);
        }
    }
    return badNodes;
}

export function run() {
    let commandLineArgs = process.argv.slice(2);
    if (commandLineArgs.length === 0) {
        console.log("Command line error: no arguments");
        process.exit(-1);
    }
    let cmdOptions = parseCommandLine(commandLineArgs);
    
    if(!cmdOptions.IDE_Mode) {
        let result = lint(cmdOptions);
        process.exit(result > 0 ? 1 : 0);
    } else {
        run_IDE_mode(cmdOptions);
    }
}

function getTempFileName() {
  return path.join(os.tmpdir(), Math.floor((Math.random() * 10000000)).toString() + "_linter_tmp_file.ts");
}

function run_IDE_mode(cmdOptions: CommandLineOptions) {
    TypeScriptLinter.IDE_mode = true;
    const tmpFileName = getTempFileName();
    // read data from stdin
    let writeStream = fs.createWriteStream(tmpFileName, {flags: 'w'} );

    const rl = readline.createInterface({
        input: process.stdin,
        output: writeStream,
        terminal: false
    });

    rl.on('line', (line:string) => {
        fs.appendFileSync(tmpFileName, line + '\n');
    });
    let ready = false
    rl.once('close', () => {
        // end of input
        writeStream.close();

        cmdOptions.InputFiles = [tmpFileName];
        if (cmdOptions.ParsedConfigFile) {
            cmdOptions.ParsedConfigFile.fileNames.push(tmpFileName);
        }

        lint(cmdOptions);
        
        let jsonMessage = TypeScriptLinter.badNodeInfos.map(x => ({
            line: x.line,
            column: x.column,
            start: x.start,
            end: x.end,
            type: x.type,
            suggest: x.suggest,
            rule: x.rule
        }));
        console.log("{\"linter messages\":" + JSON.stringify(jsonMessage) + "}");
        fs.unlinkSync(tmpFileName);
    });
}