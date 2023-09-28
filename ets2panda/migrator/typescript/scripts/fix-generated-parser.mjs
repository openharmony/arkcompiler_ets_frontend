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

/* 
 * This script is intended to fix lexer and parser files generated
 * by 'antlr4ts' by adding missing imports for base classes.
*/

import { openSync, readFileSync, writeSync, closeSync } from "fs";
import { EOL } from "os";

function appendText(file, textToAppend) {
    var error;
    try {
        var data = readFileSync(file); // Read existing contents into data
        var fd = openSync(file, 'w+');
        var buffer = Buffer.from(textToAppend + EOL);

        writeSync(fd, buffer, 0, buffer.length, 0); // Write new data
        writeSync(fd, data, 0, data.length, buffer.length); // Append old data
    } catch (e) {
        error = e;
    } finally {
        closeSync(fd);

        if (error) {
            console.error(error);
            process.exit(1);
        }
    }
}

var base_dir = process.argv[2];

var lexer_imports = 'import { StaticTSLexerBase } from "../../src/staticts/StaticTSLexerBase"'
appendText(`${base_dir}/StaticTSLexer.ts`, lexer_imports);

var parser_imports = `import { StaticTSParserBase } from "../../src/staticts/StaticTSParserBase"
import { StaticTSContextBase } from "../../src/staticts/StaticTSContextBase"`
appendText(`${base_dir}/StaticTSParser.ts`, parser_imports);
