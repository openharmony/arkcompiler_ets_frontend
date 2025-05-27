/*
 * Copyright (c) 2024 - 2025 Huawei Device Co., Ltd.
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

import { LOG_LEVEL } from 'arkanalyzer';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';

export class ProjectConfig {
    projectName: string;
    projectPath: string;
    logPath: string;
    ohosSdkPath: string;
    hmsSdkPath: string;
    checkPath: string;
    apiVersion: number;
    fix: string;
    fixSelected: boolean;
    npmPath: string;
    npmInstallDir: string;
    reportDir: string;
    sdksThirdParty: string[];
    arkCheckPath: string;
    product: string;
    logLevel: LOG_LEVEL;
    arkAnalyzerLogLevel: LOG_LEVEL;


    // [filePath, languageTag] or [folderPath, languageTag]
    languageTags: Map<string, Language>;
    // [...filePaths, ...folderPaths]
    fileOrFolderToCheck: string[];

    constructor(config: any) {
        this.projectName = config.projectName ?? '';
        this.projectPath = config.projectPath ?? '';
        this.logPath = config.logPath ?? '';
        this.ohosSdkPath = config.ohosSdkPath ?? '';
        this.hmsSdkPath = config.hmsSdkPath ?? '';
        this.checkPath = config.checkPath ?? '';
        this.apiVersion = config.sdkVersion ?? 14;
        this.fix = config.fix ?? 'false';
        this.fixSelected = config.fixSelected ?? false;
        this.npmPath = config.npmPath ? config.npmPath : 'npm';
        this.npmInstallDir = config.npmInstallDir ? config.npmInstallDir : './';
        this.reportDir = config.reportDir ? config.reportDir : './';
        this.sdksThirdParty = config.sdksThirdParty ?? [];
        this.arkCheckPath = config.arkCheckPath ?? '';
        this.product = config.product ?? '';
        this.languageTags = config.languageTags ?? new Map();
        this.fileOrFolderToCheck = config.fileOrFolderToCheck ?? [];
        this.logLevel = config.logLevel ?? LOG_LEVEL.INFO;
        this.arkAnalyzerLogLevel = config.arkAnalyzerLogLevel ?? LOG_LEVEL.ERROR;
    }
}

export interface SelectedFileInfo {
    filePath: string;
    fixKey?: string[];
}

export class FileToCheck implements SelectedFileInfo {
    public filePath: string;

    constructor(filePath: string) {
        this.filePath = filePath;
    }
}