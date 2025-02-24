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
  BuildConfigType,
  processBuildConfig
} from './init/process_build_config';
import { BuildMode } from './build/build_mode';
import { BUILD_TYPE_BUILD } from './pre_define';
import { Logger } from './logger';

export function build(projectConfig: Record<string, BuildConfigType>): void {
  Logger.getInstance(projectConfig);
  let buildConfig: Record<string, BuildConfigType> = processBuildConfig(projectConfig);

  if (projectConfig.buildType === BUILD_TYPE_BUILD) {
    let buildMode: BuildMode = new BuildMode(buildConfig);
    buildMode.run();
  }
}

function main(): void {
  console.log(process.argv);

  const buildConfigPath: string = path.resolve(process.argv[2]);
  const projectConfig: Record<string, BuildConfigType> = JSON.parse(fs.readFileSync(buildConfigPath, 'utf-8'));

  build(projectConfig);
}

main();
