/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import type {IOptions} from './IOptions';

export interface ArkGuardOptions {
  /**
   * path of open harmony sdk
   */
  sdkPath?: string,

  /**
   * api version of open harmony sdk
   */
  apiVersion?: string,

  /**
   * Protection level specified by user
   */
  protectedLevel?: boolean;

  /**
   * whether to turn on source map function.
   */
  sourceMap?: boolean,
  /**
   * specify the path of  name cache file, use in hot update.
   */
  nameCache?: string,

  /**
   * output directory for obfuscated results.
   */
  outDir?: string,

  /**
   * obfuscation options
   */
  obfuscations?: IOptions,
}
