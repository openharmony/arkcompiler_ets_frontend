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

import { existsSync, copyFileSync } from 'node:fs';
import * as path from 'node:path';
import { exit } from 'node:process';

const SCRIPTS = [
    'print_cmd_line_args.bat',
    'print_cmd_line_args.js',
    'print_cmd_line_args.sh',
]

function reportErrorAndExit(msg) {
    console.log(msg);
    exit(1);
}

function copyTestRunnerScriptsToBuild() {
    const srcDir = path.join('scripts', 'testRunner');
    const distDir = path.join('build', 'testRunner');
    if (!existsSync(srcDir)) {
        reportErrorAndExit('Failed to locate ' + srcDir + ' directory');
    }
    if (!existsSync(distDir)) {
        reportErrorAndExit('Failed to locate ' + distDir + ' directory');
    }
    for (const script of SCRIPTS) {
        const srcPath = path.resolve(srcDir, script);
        const distPath = path.resolve(distDir, script);
        copyFileSync(srcPath, distPath);
    }
}

copyTestRunnerScriptsToBuild();