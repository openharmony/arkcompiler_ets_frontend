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
const sourceMap = require('source-map');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..', '..');
const COVERAGE_DIR = path.join(PROJECT_ROOT, 'coverage');
const COVERAGE_FILE = path.join(COVERAGE_DIR, 'coverage.json');
const NEW_COVERAGE_FILE = path.join(COVERAGE_DIR, 'newCoverage.json');

/**
 * Processes statement map data using source map consumer
 * @param {Object} statementMap - Statement map data
 * @param {Object} consumer - Source map consumer
 */
function processStatementMap(statementMap, consumer) {
    for (const id in statementMap) {
        const statement = statementMap[id];
        const startPos = consumer.originalPositionFor(statement.start);
        const endPos = consumer.originalPositionFor(statement.end);
        
        statement.start = { line: startPos.line, column: startPos.column };
        statement.end = { line: endPos.line, column: endPos.column };
    }
}

/**
 * Processes function map data using source map consumer
 * @param {Object} functionMap - Function map data
 * @param {Object} consumer - Source map consumer
 */
function processFunctionMap(functionMap, consumer) {
    for (const id in functionMap) {
        const func = functionMap[id];
        
        const declStart = consumer.originalPositionFor(func.decl.start);
        const declEnd = consumer.originalPositionFor(func.decl.end);
        const locStart = consumer.originalPositionFor(func.loc.start);
        const locEnd = consumer.originalPositionFor(func.loc.end);
        
        func.decl = {
            start: { line: declStart.line, column: declStart.column },
            end: { line: declEnd.line, column: declEnd.column }
        };
        
        func.loc = {
            start: { line: locStart.line, column: locStart.column },
            end: { line: locEnd.line, column: locEnd.column }
        };
        
        func.line = declStart.line;
    }
}

/**
 * Processes branch map data using source map consumer
 * @param {Object} branchMap - Branch map data
 * @param {Object} consumer - Source map consumer
 */
function processBranchMap(branchMap, consumer) {
    for (const id in branchMap) {
        const branch = branchMap[id];
        
        // Process locations
        branch.locations.forEach(location => {
            const startPos = consumer.originalPositionFor(location.start);
            const endPos = consumer.originalPositionFor(location.end);
            
            location.start = { line: startPos.line, column: startPos.column };
            location.end = { line: endPos.line, column: endPos.column };
        });
        
        // Process loc
        const locStart = consumer.originalPositionFor(branch.loc.start);
        const locEnd = consumer.originalPositionFor(branch.loc.end);
        
        branch.loc = {
            start: { line: locStart.line, column: locStart.column },
            end: { line: locEnd.line, column: locEnd.column }
        };
        
        branch.line = locStart.line;
    }
}

/**
 * Collects and processes coverage data using source maps
 */
async function collectCoverage() {
    if (!fs.existsSync(COVERAGE_FILE)) {
        throw new Error(`Coverage file not found: ${COVERAGE_FILE}`);
    }

    const coverageData = JSON.parse(fs.readFileSync(COVERAGE_FILE, 'utf8'));
    const newCoverageData = {};

    for (const file in coverageData) {
        const mapFile = `${file}.map`;
        
        if (!fs.existsSync(mapFile)) {
            console.warn(`Source map not found for: ${file}`);
            continue;
        }

        const sourceMapData = JSON.parse(fs.readFileSync(mapFile, 'utf8'));
        const sources = sourceMapData.sources;
        const newFile = path.join(path.dirname(mapFile), sources[0]);

        await sourceMap.SourceMapConsumer.with(sourceMapData, null, (consumer) => {
            const fileCoverage = { ...coverageData[file] };
            fileCoverage.path = newFile;
            
            processStatementMap(fileCoverage.statementMap, consumer);
            processFunctionMap(fileCoverage.functionMap, consumer);
            processBranchMap(fileCoverage.branchMap, consumer);
            
            newCoverageData[newFile] = fileCoverage;
        });
    }

    fs.writeFileSync(
        NEW_COVERAGE_FILE,
        JSON.stringify(newCoverageData, null, 4)
    );
}

// Execute and handle errors
collectCoverage()
    .then(() => console.log('Coverage collection completed successfully'))
    .catch(error => {
        console.error('Error collecting coverage:', error);
        process.exit(1);
    });