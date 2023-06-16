/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Command, ParseOptionsResult } from "commander";
import * as path from "path";
import * as ts from "typescript";
import { LOGE } from "./log";
import { execute, getDtsFiles } from "./base/util";

export class CmdOptions {
    private static cmd: Command = new Command();
    private static options: any = undefined;
    private static unknownOpts: ts.ParsedCommandLine;

    static initOptions(): void {
        this.cmd
            .option('-m, --modules', 'compile as module.', false)
            .option('-l, --debug-log', 'show info debug log and generate the json file.', false)
            .option('-a, --dump-assembly', 'dump assembly to file.', false)
            .option('-d, --debug', 'compile with debug info.', false)
            .option('-w, --debug-add-watch <args...>', 'watch expression and abc file path in debug mode.', [])
            .option('-k, --keep-persistent-watch <watchArgs...>',
                    'keep persistent watch on js file with watched expression.', [])
            .option('-s, --show-statistics <items...>', 'show compile statistics(ast, histogram, hoisting, all).', [''])
            .option('-o, --output <outputFile>', 'set output file.', '')
            .option('-t, --timeout <time>', 'js to abc timeout threshold(unit: seconds).', "0")
            .option('--opt-log-level <level>', 'specifie optimizer log level.   \
                Possible values: [debug, info, error, fatal]', 'error')
            .option('--opt-level <level>', 'Optimization level. Possible values: [0, 1, 2]. Default: 0\n    \
                0: no optimizations\n    \
                1: basic bytecode optimizations, including valueNumber, lowering, constantResolver, regAccAllocator\n  \
                2: other bytecode optimizations, unimplemented yet', "1")
            .option('-h, --help', 'Show usage guide.', false)
            .option('-v, --bc-version', 'Print ark bytecode version', false)
            .option('--bc-min-version', 'Print ark bytecode minimum supported version', false)
            .option('-i, --included-files <files...>', 'The list of dependent files.', [])
            .option('-p, --record-type', 'Record type info. Default: true', false)
            .option('-q, --dts-type-record', 'Record type info for .d.ts files. Default: false', false)
            .option('-g, --debug-type', 'Print type-related log. Default: false', false)
            .option('--output-type', 'set output type.', false)
            .option('--source-file <file>', 'specify the file path info recorded in generated abc', '')
            .option('--generate-tmp-file', 'whether to generate intermediate temporary files', false)
    }

    // @ts-ignore
    static parseUserCmd(args: string[]) {
        this.initOptions();
        let parsedResult: ParseOptionsResult = this.cmd.parseOptions(process.argv);
        this.options = this.cmd.opts();

        if (this.options.help) {
            this.showHelp();
            return undefined;
        }

        if (this.isBcVersion() || this.isBcMinVersion()) {
            this.getVersion(this.isBcVersion());
            return undefined;
        }

        parsedResult.operands = parsedResult.operands.slice(2);
        if (parsedResult.operands.length === 0 && this.getDeamonModeArgs().length === 0 &&
            !this.isWatchEvaluateExpressionMode()) {
            LOGE("options at least one file is needed");
            this.showHelp();
            return undefined;
        }

        let dtsFiles = getDtsFiles(path["join"](__dirname, "../node_modules/typescript/lib"));
        this.unknownOpts = ts.parseCommandLine(parsedResult.operands);
        this.unknownOpts.fileNames.push(...dtsFiles);
        return this.unknownOpts;
    }

    static showHelp(): void {
        this.cmd.outputHelp();
    }

    static isBcVersion(): boolean {
        return this.options ? this.options.bcVersion : false;
    }

    static isBcMinVersion(): boolean {
        return this.options ? this.options.bcMinVersion : false;
    }

    static getVersion(isBcVersion: boolean = true): void {
        let js2abc = path.join(path.resolve(__dirname, '../bin'), "js2abc");
        let version_arg = isBcVersion ? "--bc-version" : "--bc-min-version";
        execute(`${js2abc}`, [version_arg]);
    }

    static setWatchEvaluateExpressionArgs(watchArgs: string[]) {
        this.options.debugAddWatch = watchArgs;
    }

    static getDeamonModeArgs(): string[] {
        return this.options ? this.options.keepPersistentWatch : [];
    }

    static isWatchEvaluateDeamonMode(): boolean {
        return CmdOptions.getDeamonModeArgs()[0] == "start";
    }

    static isStopEvaluateDeamonMode(): boolean {
        return CmdOptions.getDeamonModeArgs()[0] == "stop";
    }

    static getEvaluateDeamonPath(): string {
        return CmdOptions.getDeamonModeArgs()[1];
    }

    static isWatchEvaluateExpressionMode(): boolean {
        return this.options ? this.options.debugAddWatch.length != 0 : false;
    }

    static getEvaluateExpression(): string {
        return this.options.debugAddWatch[0];
    }

    static getWatchJsPath(): string {
        return this.options.debugAddWatch[1];
    }

    static getWatchTimeOutValue(): number {
        return this.options.debugAddWatch.length == 2 ? 0 : this.options.debugAddWatch[2];
    }

    static getIncludedFiles(): string[] {
        return this.options ? this.options.includedFiles : [];
    }

    static getInputFileName(): string {
        let path = this.unknownOpts.fileNames[0];
        let inputFile = path.substring(0, path.lastIndexOf('.'));
        return inputFile;
    }

    static getOutputBinName(): string {
        let outputFile = this.options.output;
        if (outputFile == "") {
            outputFile = CmdOptions.getInputFileName() + ".abc";
        }
        return outputFile;
    }

    static needRecordType(): boolean {
        return this.options ? !this.options.recordType : false;
    }

    static needRecordDtsType(): boolean {
        return this.options ? this.options.dtsTypeRecord : false;
    }

    static isAssemblyMode(): boolean {
        return this.options ? this.options.dumpAssembly : false;
    }

    static isEnableDebugLog(): boolean {
        return this.options ? this.options.debugLog : false;
    }

    static isDebugMode(): boolean {
        return this.options ? this.options.debug : false;
    }

    static isModules(): boolean {
        return this.options ? this.options.modules : false;
    }

    static getOptLevel(): number {
        return this.options ? Number.parseFloat(this.options.optLevel) : 0;
    }

    static getOptLogLevel(): string {
        return this.options ? this.options.optLogLevel : "";
    }

    static showASTStatistics(): boolean {
        return !this.options ? false :
            this.options.showStatistics.includes("ast") || this.options.showStatistics.includes("all");
    }

    static showHistogramStatistics(): boolean {
        return !this.options ? false :
            this.options.showStatistics.includes("histogram") || this.options.showStatistics.includes("all");
    }

    static showHoistingStatistics(): boolean {
        return !this.options ? false :
            this.options.showStatistics.includes("hoisting") || this.options.showStatistics.includes("all");
    }

    static getTimeOut(): Number {
        return this.options ? Number.parseFloat(this.options.timeout) : 0;
    }

    static isOutputType(): false {
        return this.options ? this.options.outputType : false;
    }

    static enableTypeLog(): boolean {
        return this.options ? this.options.debugType : false;
    }

    static getSourceFile(): string {
        return this.options ? this.options.sourceFile : "";
    }

    static needGenerateTmpFile(): boolean {
        return this.options ? this.options.generateTmpFile : false;
    }
}
