/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { CheckEntry, checkEntryBuilder } from '../../utils/common/CheckEntry';
import { RuleConfig } from '../../model/RuleConfig';
import { ProjectConfig } from '../../model/ProjectConfig';
import { Utils } from '../../utils/common/Utils';
import { CheckerStorage } from '../../utils/common/CheckerStorage';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { FileUtils } from '../../utils/common/FileUtils';
import { DefaultMessage } from '../../model/Message';
import { FileIssues } from '../../model/Defects';
import { CallGraphHelper, DVFGHelper, GlobalCallGraphHelper } from '../../checker/migration/Utils';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'MigrationTool');

export class MigrationTool {
    private checkEntry: CheckEntry;

    constructor(ruleConfig: any, projectConfig: any) {
        this.checkEntry = new CheckEntry();
        // 解析规则配置文件
        this.checkEntry.ruleConfig = new RuleConfig(ruleConfig);
        // 解析项目配置文件
        this.checkEntry.projectConfig = new ProjectConfig(projectConfig);
    }

    public async buildCheckEntry(): Promise<Boolean> {
        // 日志配置
        const logPath = this.checkEntry.projectConfig.logPath;
        Utils.setLogConfig(logPath.length === 0 ? './HomeCheck.log' : logPath,
            this.checkEntry.projectConfig.arkAnalyzerLogLevel,
            this.checkEntry.projectConfig.logLevel);
        logger.info(`buildCheckEntry start`);
        // api版本配置
        CheckerStorage.getInstance().setApiVersion(this.checkEntry.projectConfig.apiVersion);
        // product配置
        CheckerStorage.getInstance().setProduct(this.checkEntry.projectConfig.product);
        // 设置指定文件检查，不设置默认检查所有文件
        this.checkEntry.setCheckFileList(FileUtils.getFileInfoFromFileList(this.checkEntry.projectConfig.fileOrFolderToCheck));

        // 外部没有建立消息通道，使用默认通道
        if (!this.checkEntry.message) {
            this.checkEntry.message = new DefaultMessage();
        }

        // 前处理
        if (!await checkEntryBuilder(this.checkEntry)) {
            return false;
        }
        logger.info(`buildCheckEntry end`);
        return true;
    }

    public async start(): Promise<FileIssues[]> {
        logger.info(`MigrationTool run start`);
        await this.checkEntry.runAll();

        let result = this.checkEntry.sortIssues();
        this.dispose();
        logger.info(`MigrationTool run end`);
        return result;
    }

    private dispose(): void {
        CallGraphHelper.dispose();
        GlobalCallGraphHelper.dispose();
        DVFGHelper.dispose();
        CheckerStorage.dispose();
        this.checkEntry.scene.dispose();
    }
}