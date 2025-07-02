/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

const fs = require('fs');
const path = require('path');

const projectRoot = path.join(__dirname, '..', '..');
const buildDir = path.join(projectRoot, 'build');
const coverageDir = path.join(projectRoot, 'coverage');
const buildInstrumentDir = path.join(coverageDir, 'build_instrument');

function copyDirectory(src, dest) {
    fs.mkdirSync(dest, { recursive: true });

    const entries = fs.readdirSync(src, { withFileTypes: true });

    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);

        if (entry.isDirectory()) {
            copyDirectory(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

function prepareCoverage() {
    try {
        if (fs.existsSync(coverageDir)) {
            fs.rmSync(coverageDir, { recursive: true, force: true });
        }

        fs.mkdirSync(coverageDir, { recursive: true });
        fs.mkdirSync(buildInstrumentDir, { recursive: true });

        copyDirectory(buildDir, buildInstrumentDir);

        const dataDir = path.join(projectRoot, 'src', 'data');
        const instrumentDataDir = path.join(buildInstrumentDir, 'data');
        
        if (fs.existsSync(dataDir)) {
            copyDirectory(dataDir, instrumentDataDir);
        }
    } catch (error) {
        console.error('Error during coverage preparation:', error);
        process.exit(1);
    }
}

prepareCoverage();