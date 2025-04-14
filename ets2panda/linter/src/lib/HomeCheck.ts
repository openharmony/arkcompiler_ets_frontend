/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
import type { CommandLineOptions } from './CommandLineOptions';

interface RuleConfigInfo {
  ruleSet: string[];
}

interface ProjectConfigInfo {
  projectName: string | undefined;
  projectPath: string | undefined;
  logPath: string;
  arkCheckPath: string;
  ohosSdkPath: string;
  hmsSdkPath: string;
  reportDir: string;
  languageTags: Map<string, number>;
  fileOrFolderToCheck: string[];
}

export function getHomeCheckConfigInfo(cmdOptions: CommandLineOptions): {
  ruleConfigInfo: RuleConfigInfo;
  projectConfigInfo: ProjectConfigInfo;
} {
  const languageTags = new Map<string, number>();
  const inputFiles = cmdOptions.inputFiles;
  inputFiles.forEach((file) => {
    languageTags.set(file, 2);
  });
  const ruleConfigInfo = {
    ruleSet: ['plugin:@migration/all']
  };
  const projectConfigInfo = {
    projectName: cmdOptions.arktsWholeProjectPath,
    projectPath: cmdOptions.arktsWholeProjectPath,
    logPath: './HomeCheck.log',
    arkCheckPath: './node_modules/homecheck',
    ohosSdkPath: cmdOptions.sdkDefaultApiPath ? cmdOptions.sdkDefaultApiPath : '',
    hmsSdkPath: cmdOptions.sdkExternalApiPath ? cmdOptions.sdkExternalApiPath[0] : '',
    reportDir: './',
    languageTags: languageTags,
    fileOrFolderToCheck: inputFiles
  };
  return { ruleConfigInfo, projectConfigInfo };
}
