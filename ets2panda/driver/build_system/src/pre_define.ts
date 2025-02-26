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

export const ETS_SUFFIX: string = '.ets';
export const ABC_SUFFIX: string = '.abc';

export const BUILD_TYPE_BUILD: string = 'build';
export enum BUILD_MODE {
    DEBUG = 'Debug',
    RELEASE = 'Release'
};

export const PANDA_SDK_PATH_FROM_SDK: string = './build-tools/ets2panda';
export const SYSTEM_SDK_PATH_FROM_SDK: string = './';