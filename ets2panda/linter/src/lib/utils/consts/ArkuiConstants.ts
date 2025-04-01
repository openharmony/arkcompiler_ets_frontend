/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export const DOUBLE_DOLLAR_IDENTIFIER = '$$';
export const THIS_IDENTIFIER = 'this';
export const ATTRIBUTE_SUFFIX = 'Attribute';
export const INSTANCE_IDENTIFIER = 'instance';
export const COMMON_METHOD_IDENTIFIER = 'CommonMethod';
export const APPLY_STYLES_IDENTIFIER = 'applyStyles';
export const STATE_STYLES = 'stateStyles';
export const ARKUI_PACKAGE_NAME = '@kits.ArkUI';
export const VALUE_IDENTIFIER = 'value';

export enum CustomDecoratorName {
  Extend = 'Extend',
  Styles = 'Styles',
  AnimatableExtend = 'AnimatableExtend',
  Memo = 'Memo',
  Observed = 'Observed'
}

export const observedDecoratorName: Set<string> = new Set([
  'State',
  'Prop',
  'Link',
  'Provide',
  'Consume',
  'LocalStorageProp',
  'LocalStorageLink',
  'StorageProp',
  'StorageLink',
  'Track'
]);

export const skipImportDecoratorName: Set<string> = new Set(['Extend', 'Styles', 'Sendable', 'Concurrent']);
