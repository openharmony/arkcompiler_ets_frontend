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
  buildConfig,
  BuildConfigType,
  processBuildConfig
} from './init/process_build_config';
import { BuildMode } from './build/build_mode';

export function build(projectConfig: Record<string, BuildConfigType>): void {
  processBuildConfig(projectConfig);

  if (projectConfig.buildMode === 'build') {
    let buildMode: BuildMode = new BuildMode(buildConfig);
    buildMode.run();
  }
}


function main(): void {
  console.log(process.argv);
  let file: string = process.argv[2]; // input file

  let projectConfig: Record<string, BuildConfigType> = {
    entryFiles: [path.resolve(file)],
    buildMode: 'build',
    outputDir: __dirname,
    compileToolPath:
      path.resolve(__dirname, '..', 'node_modules', 'libarkts', 'arkoala-arkts', 'node_modules', '@panda', 'sdk')
  };

  build(projectConfig);
}

main();