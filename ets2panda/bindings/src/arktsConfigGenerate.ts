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

import { BuildMode } from './build/buildMode';
import { BuildConfig } from './types';
import { ModuleDescriptor, generateBuildConfigs } from './buildConfigGenerate';
import { PANDA_SDK_PATH_FROM_SDK } from './preDefine';

import * as fs from 'fs';
import * as path from 'path';
import { PluginDriver } from './ui_plugins_driver';

function processBuildConfig(projectConfig: BuildConfig): BuildConfig {
  let buildConfig: BuildConfig = { ...projectConfig };
  let buildSdkPath: string = buildConfig.buildSdkPath as string;
  buildConfig.pandaSdkPath = buildConfig.pandaSdkPath ?? path.resolve(buildSdkPath, PANDA_SDK_PATH_FROM_SDK);
  PluginDriver.getInstance().initPlugins(buildConfig);
  return buildConfig;
}

export function generateArkTsConfigByModules(
  buildSdkPath: string,
  projectRoot: string,
  modules?: ModuleDescriptor[]
): void {
  const allBuildConfig = generateBuildConfigs(buildSdkPath, projectRoot, modules);
  let compileFileInfos: Record<string, string> = {};
  const cacheDir = path.join(projectRoot, '.idea', '.deveco');
  const compileFileInfosPath = path.join(cacheDir, 'lsp_compileFileInfos.json');
  Object.keys(allBuildConfig).forEach((moduleName) => {
    const moduleConfig = allBuildConfig[moduleName] as BuildConfig;
    const processedConfig = processBuildConfig(moduleConfig);

    const buildMode = new BuildMode(processedConfig);
    buildMode.generateArkTSConfig(compileFileInfos);
  });
  try {
    const jsonCompileFileInfos = JSON.stringify(compileFileInfos, null, 2);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.writeFileSync(compileFileInfosPath, jsonCompileFileInfos, 'utf-8');
  } catch (err) {
    console.error(`Failed to write compileFileInfos to ${compileFileInfosPath} with error: ${err}`);
  }
}
