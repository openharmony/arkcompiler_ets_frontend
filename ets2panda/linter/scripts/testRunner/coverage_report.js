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
const libCoverage = require('istanbul-lib-coverage');
const libReport = require('istanbul-lib-report');
const reports = require('istanbul-reports');

const projectRoot = path.join(__dirname, '..', '..');
const coverageDir = path.join(projectRoot, 'coverage');

const coverageFile = fs.readFileSync(path.join(coverageDir, 'newCoverage.json'), 'utf8');
const coverageData = JSON.parse(coverageFile);
const coverageMap = libCoverage.createCoverageMap(coverageData);

// create summary report
const summary = libCoverage.createCoverageSummary();
coverageMap.files().forEach(file => {
    const fc = coverageMap.fileCoverageFor(file);
    const s = fc.toSummary();
    summary.merge(s);
});
console.log(summary);

// Watermarks for the report
const configWatermarks = {
    statements: [50, 80],
    branches: [50, 80],
    functions: [50, 80],
    lines: [50, 80],
};
const context = libReport.createContext({
    dir: path.join(coverageDir, 'report-html'),
    defaultSummarizer: 'nested',
    watermarks: configWatermarks,
    coverageMap,
});

const report = reports.create('html', {});
report.execute(context);

const report_text = reports.create('text', {});
report_text.execute(context);