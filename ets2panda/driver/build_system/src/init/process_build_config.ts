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

import * as path from 'path';

import {
  isLinux,
  isMac,
  isWindows,
} from '../utils';
import { PluginDriver } from '../plugins/plugins_driver';

export type BuildConfigType = string | string[];
export let buildConfig: Record<string, BuildConfigType> = {};

export function processBuildConfig(projectConfig: Record<string, BuildConfigType>): void {
  buildConfig = { ...projectConfig };
  initPlatformSpecificConfig();
  PluginDriver.getInstance().initPlugins();
}

function initPlatformSpecificConfig(): void {
  const arkPlatformPath: string = buildConfig.compileToolPath as string;
  if (isWindows()) {
    buildConfig.abcLinkerPath = path.join(arkPlatformPath, 'bin', 'ark_link.exe');
    buildConfig.depAnalyzerPath = path.join(arkPlatformPath, 'bin', 'dependency_analyzer.exe');
    return;
  }

  if (isMac() || isLinux()) {
    buildConfig.abcLinkerPath = path.join(arkPlatformPath, 'bin', 'ark_link');
    buildConfig.depAnalyzerPath = path.join(arkPlatformPath, 'bin', 'dependency_analyzer');
  }
}

export function cleanUpBuildConfig(): void {
  buildConfig = {};
}
