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

export const ARKTSCONFIG_JSON_FILE: string = 'arktsconfig.json';
export const MERGED_ABC_FILE: string = 'modules_static.abc';
export const LINKER_INPUT_FILE: string = 'fileInfo.txt';
export const DEPENDENCY_INPUT_FILE: string = 'dependencyFileInfo.txt';
export const DEPENDENCY_JSON_FILE: string = 'dependency.json';
export const PROJECT_BUILD_CONFIG_FILE: string = 'projectionConfig.json';
export const STATIC_RECORD_FILE: string = 'static.Record.d.ts';

export const DECL_ETS_SUFFIX: string = '.d.ets';
export const DECL_TS_SUFFIX: string = '.d.ts';
export const ETS_SUFFIX: string = '.ets';
export const TS_SUFFIX: string = '.ts';
export const ABC_SUFFIX: string = '.abc';

export const BUILD_TYPE_BUILD: string = 'build';
export enum BUILD_MODE {
  DEBUG = 'Debug',
  RELEASE = 'Release'
};

export enum LANGUAGE_VERSION {
  ARKTS_1_2 = '1.2',
  ARKTS_1_1 = '1.1',
  ARKTS_HYBRID = 'hybrid',
};

export const PANDA_SDK_PATH_FROM_SDK: string = './build-tools/ets2panda';
export const SYSTEM_SDK_PATH_FROM_SDK: string = './';
export const KOALA_WRAPPER_PATH_FROM_SDK: string = './build-tools/koala-wrapper/build/lib/es2panda';

export const DEFAULT_WOKER_NUMS: number = 4;

export const ETS_1_1 = 'ets1.1';
export const ETS_1_1_INTEROP = 'ets1.1interop';

export const STATIC_RECORD_FILE_CONTENT: string = `// generated for static Record
export type Record<K extends keyof any, T> = {
  [P in K]: T;
};
`;
