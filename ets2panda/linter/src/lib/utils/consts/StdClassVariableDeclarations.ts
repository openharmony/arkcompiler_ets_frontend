/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * TS/JS standard classes defined in TypeScript stdlib as ambient global variables
 * with interface-based constructor type.
 */

export const StdClassVarDecls = new Map<string, string>([
  ['Object', 'ObjectConstructor'],
  ['Function', 'FunctionConstructor'],
  ['String', 'StringConstructor'],
  ['Boolean', 'BooleanConstructor'],
  ['Number', 'NumberConstructor'],
  ['Math', 'Math'],
  ['Date', 'DateConstructor'],
  ['RegExp', 'RegExpConstructor'],
  ['Error', 'ErrorConstructor'],
  ['EvalError', 'EvalErrorConstructor'],
  ['RangeError', 'RangeErrorConstructor'],
  ['ReferenceError', 'ReferenceErrorConstructor'],
  ['SyntaxError', 'SyntaxErrorConstructor'],
  ['TypeError', 'TypeErrorConstructor'],
  ['URIError', 'URIErrorConstructor'],
  ['AggregateError', 'AggregateErrorConstructor'],
  ['JSON', 'JSON'],
  ['Array', 'ArrayConstructor'],
  ['ArrayBuffer', 'ArrayBufferConstructor'],
  ['DataView', 'DataViewConstructor'],
  ['Int8Array', 'Int8ArrayConstructor'],
  ['Uint8Array', 'Uint8ArrayConstructor'],
  ['Uint8ClampedArray', 'Uint8ClampedArrayConstructor'],
  ['Int16Array', 'Int16ArrayConstructor'],
  ['Uint16Array', 'Uint16ArrayConstructor'],
  ['Int32Array', 'Int32ArrayConstructor'],
  ['Uint32Array', 'Uint32ArrayConstructor'],
  ['Float32Array', 'Float32ArrayConstructor'],
  ['Float64Array', 'Float64ArrayConstructor'],
  ['Map', 'MapConstructor'],
  ['WeakMap', 'WeakMapConstructor'],
  ['Set', 'SetConstructor'],
  ['WeakSet', 'WeakSetConstructor'],
  ['Promise', 'PromiseConstructor'],
  ['Proxy', 'ProxyConstructor'],
  ['Symbol', 'SymbolConstructor'],
  ['SharedArrayBuffer', 'SharedArrayBufferConstructor'],
  ['Atomics', 'Atomics'],
  ['BigInt', 'BigIntConstructor'],
  ['BigInt64Array', 'BigInt64ArrayConstructor'],
  ['BigUint64Array', 'BigUint64ArrayConstructor'],
  ['WeakRef', 'WeakRefConstructor'],
  ['FinalizationRegistry', 'FinalizationRegistryConstructor']
]);
