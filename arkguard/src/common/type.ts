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

export const enum Extension {
  TS = '.ts',
  DTS = '.d.ts',
  JS = '.js',
  JSON = '.json',
  ETS = '.ets',
  DETS = '.d.ets'
}

export const supportedRunningExtension: readonly string[] = [Extension.TS, Extension.JS];
export const supportedDeclarationExtension: readonly string[] = [Extension.DTS, Extension.DETS];