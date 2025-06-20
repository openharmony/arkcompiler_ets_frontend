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
export const ARKUI_PACKAGE_NAME = '@kit.ArkUI';
export const VALUE_IDENTIFIER = 'value';
export const INDENT_STEP = 2;
export const MAKE_OBSERVED = 'makeObserved';
export const ARKUI_STATE_MANAGEMENT = '@ohos.arkui.StateManagement';
export const NEW_PROP_DECORATOR_SUFFIX = 'Ref';

export enum CustomDecoratorName {
  Extend = 'Extend',
  LocalBuilder = 'LocalBuilder',
  Styles = 'Styles',
  AnimatableExtend = 'AnimatableExtend',
  Memo = 'Memo',
  Observed = 'Observed',
  CustomLayout = 'CustomLayout',
  CustomStyles = 'CustomStyles'
}

export enum StorageTypeName {
  LocalStorage = 'LocalStorage',
  AppStorage = 'AppStorage'
}

export enum PropDecoratorName {
  Prop = 'Prop',
  StorageProp = 'StorageProp',
  LocalStorageProp = 'LocalStorageProp'
}

export enum PropFunctionName {
  Prop = 'prop',
  SetAndProp = 'setAndProp'
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

export const skipImportDecoratorName: Set<string> = new Set([
  'Extend',
  'Styles',
  'Sendable',
  'Concurrent',
  'LocalBuilder',
  'Prop',
  'StorageProp',
  'LocalStorageProp'
]);

export const customLayoutFunctionName: Set<string> = new Set(['onMeasureSize', 'onPlaceChildren']);

export const ENTRY_DECORATOR_NAME = 'Entry';
export const ENTRY_STORAGE_PROPERITY = 'storage';
export const LOCAL_STORAGE_TYPE_NAME = 'LocalStorage';
export const GET_LOCAL_STORAGE_FUNC_NAME = '__get_local_storage__';

export const PROVIDE_DECORATOR_NAME = 'Provide';
export const PROVIDE_ALIAS_PROPERTY_NAME = 'alias';
export const PROVIDE_ALLOW_OVERRIDE_PROPERTY_NAME = 'allowOverride';
