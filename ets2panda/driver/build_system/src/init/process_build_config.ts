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

import * as fs from 'fs';
import * as path from 'path';

import {
  isLinux,
  isMac,
  isWindows,
} from '../utils';
import { PluginDriver } from '../plugins/plugins_driver';
import { PANDA_SDK_PATH_FROM_SDK } from '../pre_define';
import {
  LogData,
  LogDataFactory,
  Logger
} from '../logger';
import { ErrorCode } from '../error_code';

export type BuildConfigType = string | string[] | object;

export function processBuildConfig(projectConfig: Record<string, BuildConfigType>): Record<string, BuildConfigType> {
  let buildConfig: Record<string, BuildConfigType> = { ...projectConfig };
  let buildSdkPath: string = buildConfig.buildSdkPath as string;
  buildConfig.pandaSdkPath = path.resolve(buildSdkPath, PANDA_SDK_PATH_FROM_SDK);

  initPlatformSpecificConfig(buildConfig);
  initBuildEnv(buildConfig);

  PluginDriver.getInstance().initPlugins(buildConfig.plugins as object);

  return buildConfig;
}

function initPlatformSpecificConfig(buildConfig: Record<string, BuildConfigType>): void {
  const pandaSdkPath: string = path.resolve(buildConfig.pandaSdkPath as string);
  const logger: Logger = Logger.getInstance();
  if (isWindows()) {
    buildConfig.abcLinkerPath = path.join(pandaSdkPath, 'bin', 'ark_link.exe');
  }

  if (isMac() || isLinux()) {
    buildConfig.abcLinkerPath = path.join(pandaSdkPath, 'bin', 'ark_link');
  }

  if (!fs.existsSync(buildConfig.abcLinkerPath as string)) {
    const logData: LogData = LogDataFactory.newInstance(
      ErrorCode.BUILDSYSTEM_ARK_LINK_NOT_FOUND_FAIL,
      'Ark_link not found in path.',
      '',
      buildConfig.abcLinkerPath.toString()
    );
    logger.printError(logData);
  }
}

export function initBuildEnv(buildConfig: Record<string, BuildConfigType>): void {
  const pandaSdkPath: string = path.resolve(buildConfig.pandaSdkPath as string);
  const currentPath: string | undefined = process.env.PATH;
  const logger: Logger = Logger.getInstance();

  let pandaLibPath: string = path.resolve(pandaSdkPath, 'lib');

  process.env.PATH = `${currentPath}${path.delimiter}${pandaLibPath}`;
  logger.printInfo(`Updated PATH: ${process.env.PATH}`);
}
