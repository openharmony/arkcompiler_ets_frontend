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

import { BaseMode } from './base_mode';
import { BuildConfig, ModuleInfo } from '../types';

export class BuildFrameworkMode extends BaseMode {
  frameworkMode: boolean;
  useEmptyPackage: boolean;

  constructor(buildConfig: BuildConfig) {
    super(buildConfig);
    this.mergedAbcFile = buildConfig.loaderOutPath as string;
    this.frameworkMode = buildConfig.frameworkMode ?? false;
    this.useEmptyPackage = buildConfig.useEmptyPackage ?? false;
  }

  public async run(): Promise<void> {
    super.run();
  }

  protected getMainModuleInfo(): ModuleInfo {
    let moduleInfo = super.getMainModuleInfo();
    moduleInfo.frameworkMode = this.frameworkMode;
    moduleInfo.useEmptyPackage = this.useEmptyPackage;
    return moduleInfo;
  }
}
