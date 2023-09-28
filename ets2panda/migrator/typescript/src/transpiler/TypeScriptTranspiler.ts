/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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
import { writeFileSync } from "fs";
import { TypeScriptTransformer } from "./TypeScriptTransformer";
import { CmdOptions } from "./CommandLineParser";

function compile(fileNames: string[], options: ts.CompilerOptions): ts.Program {
    let program = ts.createProgram(fileNames, options);

    // Log errors
    let diagnostics = ts.getPreEmitDiagnostics(program);
    diagnostics.forEach(diagnostic => {
        if (diagnostic.file) {
            let { line, character } = ts.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start!);
            let message = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
            console.error(`${diagnostic.file.fileName} (${line + 1},${character + 1}): ${message}`);
        } else {
            console.error(ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"));
        }
    });
    
    return program;
}

function transpile() {
    const inputFiles = CmdOptions.InputFiles;

    // Set compilation target to 'latest' ES version to enable
    // newest language features to avoid syntax errors.
    const tsProgram = compile(inputFiles, {
        noEmitOnError: true,
        noImplicitAny: true,
        target: ts.ScriptTarget.Latest,
        module: ts.ModuleKind.CommonJS,
        //skipLibCheck: true
    });

    // Retrieve AST for input files.
    let tsSrcFiles = inputFiles.map((val, idx, array) => tsProgram.getSourceFile(val));

    for(let tsSrcFile of tsSrcFiles) {
        let transformer = new TypeScriptTransformer(tsSrcFile, tsProgram);
        let stsCompUnit = transformer.transform();
        
        let xmlString = stsCompUnit.toXML();
        let xmlFile = tsSrcFile.fileName + ".xml";
        writeFileSync(xmlFile, xmlString);
    }
    
    if (CmdOptions.ConversionRateMode) {
        console.log("Conversion rate:" + (TypeScriptTransformer.getTransformationRate() * 100).toFixed(1));
    }
}

transpile();