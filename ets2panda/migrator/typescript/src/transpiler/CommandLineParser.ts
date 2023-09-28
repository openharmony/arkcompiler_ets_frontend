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

import { readFileSync } from "fs";

export interface CommandLineOptions {
    VerboseMode?: boolean;
    ConversionRateMode?: boolean;
    ConvRateVerboseMode?: boolean;
    InputFiles: string[];
}

function parse(): CommandLineOptions {
    let commandLineArgs = process.argv.slice(2);

    let opts: CommandLineOptions = {
        InputFiles: []
    };

    let idx = 0;
    while(idx < commandLineArgs.length) {
        let arg = commandLineArgs[idx];
        
        if (arg[0] === '@') {
            // Process arguments from the specified response file. Any following
            // argument on the command-line will be ignored.
            // Note: The 'filter(e => e)' call is used to remove empty strings
            // from parsed argument list.
            try {
                commandLineArgs = readFileSync(arg.slice(1)).toString().split("\n").filter(e => e);
                idx = 0;
                continue;
            } catch (error: any) {
                console.error("Failed to read response file: " + (error.message ?? error));
            }
        }
        else if (arg === "-verbose") {
            opts.VerboseMode = true;
        }
        else if (arg === "-R") {
            opts.ConversionRateMode = true;
        }
        else if (arg === "-R-verbose") {
            opts.ConvRateVerboseMode = true;
        }
        else {
            opts.InputFiles.push(arg);
        }
        idx++;
    }

    return opts;
}

// Command line arguments are singleton and evaluated
// only once during the first import of this module.
export let CmdOptions: CommandLineOptions = parse();