/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import { FaultID } from "./Problems";

/**
 * ArrayBuffer
 */
const LIMITED_STD_ARRAYBUFFER_API = [
  // properties
  // methods
  'isView'
];

/**
 * Object
 */
const LIMITED_STD_OBJECT_API = [
  // properties
  '__proto__',
  // methods
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
  'assign',
  'create',
  'defineProperties',
  'defineProperty',
  'freeze',
  'fromEntries',
  'getOwnPropertyDescriptor',
  'getOwnPropertyDescriptors',
  'getOwnPropertySymbols',
  'getPrototypeOf',
  'hasOwnProperty',
  'is',
  'isExtensible',
  'isFrozen',
  'isPrototypeOf',
  'isSealed',
  'preventExtensions',
  'propertyIsEnumerable',
  'seal',
  'setPrototypeOf',
];

/**
 * Proxy
 */
const LIMITED_STD_PROXYHANDLER_API = [
  // properties
  // methods
  'apply',
  'construct',
  'defineProperty',
  'deleteProperty',
  'get',
  'getOwnPropertyDescriptor',
  'getPrototypeOf',
  'has',
  'isExtensible',
  'ownKeys',
  'preventExtensions',
  'set',
  'setPrototypeOf'
];

/**
 * Reflect
 */
const LIMITED_STD_REFLECT_API = [
  // properties
  // methods
  'apply',
  'construct',
  'defineProperty',
  'deleteProperty',
  'getOwnPropertyDescriptor',
  'getPrototypeOf',
  'isExtensible',
  'preventExtensions',
  'setPrototypeOf',
];

/**
 * Symbol
 */
const LIMITED_STD_SYMBOL_API = [
    'Symbol',
    // properties
    'asyncIterator',
    'description',
    'hasInstance',
    'isConcatSpreadable',
    'match',
    'matchAll',
    'replace',
    'search',
    'species',
    'split',
    'toPrimitive',
    'toStringTag',
    'unscopables',
    // methods
    'for',
    'keyFor',
    'toString',
    'valueOf',
];

/**
 * Function
 */
const LIMITED_STD_FUNCTION_API = [
  // properties
  // methods
  'apply',
  'bind',
  'call',
];

/**
 * Global
 */
export const LIMITED_STD_GLOBAL_API = [
  // properties
  // methods
  'eval',
];

export const LIMITED_STD_API = new Map<string, {arr: Array<string>, fault: FaultID}> ([
  ['Object', {arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi}],
  ['ObjectConstructor', {arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi}],
  ['Reflect', {arr: LIMITED_STD_REFLECT_API, fault: FaultID.LimitedStdLibApi}],
  ['ProxyHandler', {arr: LIMITED_STD_PROXYHANDLER_API, fault: FaultID.LimitedStdLibApi}],
  ['ArrayBuffer', {arr: LIMITED_STD_ARRAYBUFFER_API, fault: FaultID.LimitedStdLibApi}],
  ['ArrayBufferConstructor', {arr: LIMITED_STD_ARRAYBUFFER_API, fault: FaultID.LimitedStdLibApi}],
  ['Symbol', {arr: LIMITED_STD_SYMBOL_API, fault: FaultID.SymbolType}],
  ['SymbolConstructor', {arr: LIMITED_STD_SYMBOL_API, fault: FaultID.SymbolType}],
  ['Function', {arr: LIMITED_STD_FUNCTION_API, fault: FaultID.FunctionApplyBindCall}],
  ['CallableFunction', {arr: LIMITED_STD_FUNCTION_API, fault: FaultID.FunctionApplyBindCall}],
])
