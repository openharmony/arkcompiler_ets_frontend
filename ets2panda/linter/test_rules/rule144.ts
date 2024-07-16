/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

/// Global
eval('console.log("foo")');
let inf = Infinity;
let nan = NaN;
isFinite(1);
isNaN(2);
parseFloat('3');
parseInt('4', 10);
encodeURI('');
encodeURIComponent('');
decodeURI('');
decodeURIComponent('');
escape('');
unescape('');

global.eval('console.log("foo")');
globalThis.eval('console.log("foo")');
const evl = "eval('console.log(1)')";
const res: void = Function(evl)();
const arr1 = ['foo', 'foo', 'foo'];

class C {}
let c = new C();
interface Obj {
    a: string;
    b: number;
    c: boolean;
}
const object1: Obj = {
    a: 'somestring',
    b: 42,
    c: false,
};

/// Object
/// Object . __proto__(),
/// Object . __defineGetter__(),
/// Object . __defineSetter__(),
/// Object . __lookupGetter__(),
/// Object . __lookupSetter__(),
Object.assign<C, C>(c, c);
Object.create(c);
Object.defineProperties<C>(c, {});
Object.defineProperty<C>(c, 'p', c);
Object.entries<C>([]);
Object.freeze(() => {});
Object.fromEntries<number>([]);
Object.getOwnPropertyDescriptor(c, 'p');
Object.getOwnPropertyDescriptors<C>(c);
Object.getOwnPropertySymbols(c);
Object.getPrototypeOf(c);
Object.hasOwnProperty('p');
Object.is(c, c);
Object.isExtensible(c);
Object.isFrozen(c);
Object.isPrototypeOf(c);
Object.isSealed(c);
Object.preventExtensions<C>(c);
Object.propertyIsEnumerable('p');
Object.seal<C>(c);
Object.setPrototypeOf(c, c);
console.log(Object.getOwnPropertyNames(object1));
console.log(Object.hasOwn(object1, 'a'));
console.log(Object.hasOwn(object1, 'toString'));
console.log(Object.keys(object1));
console.log(Object.values(object1));
console.log(Object.entries(object1));

/// Reflect
Reflect.apply<C, number[], void>(() => {}, c, []);
Reflect.construct<number[], C>(C, []);
Reflect.defineProperty(c, 'p', {});
Reflect.deleteProperty(c, 'p', );
Reflect.get<C, string>(c, 'p');
Reflect.getOwnPropertyDescriptor<C, string>(c, 'p');
Reflect.getPrototypeOf(c);
Reflect.isExtensible(c);
Reflect.preventExtensions(c);
Reflect.setPrototypeOf(c, c);
console.log(Reflect.has(object1, 'a'));
console.log(Reflect.has(object1, 'toString'));
console.log(Reflect.get(object1, 'a'));
console.log(Reflect.get(object1, 'd'));
console.log(Reflect.ownKeys(object1));
Reflect.set(object1, 'b', 43);
Reflect.set(arr1, 2, 'bar');

/// Proxy
let handler: ProxyHandler<C> = {};
if (handler.apply) handler.apply(c, c, []);
if (handler.construct) handler.construct(c, [], () => {});
if (handler.defineProperty) handler.defineProperty(c, "prop", {});
if (handler.deleteProperty) handler.deleteProperty(c, "prop");
if (handler.get) handler.get(c, "prop", {});
if (handler.getOwnPropertyDescriptor) handler.getOwnPropertyDescriptor(c, "prop");
if (handler.getPrototypeOf) handler.getPrototypeOf(c);
if (handler.has) handler.has(c, "prop");
if (handler.isExtensible) handler.isExtensible(c);
if (handler.ownKeys) handler.ownKeys(c);
if (handler.preventExtensions) handler.preventExtensions(c);
if (handler.set) handler.set(c, "prop", 1, c);
if (handler.setPrototypeOf) handler.setPrototypeOf(c, null);

/// Array
ArrayBuffer.isView({});
let a: number[] = [];
let b = new ArrayBuffer(1);
Array.isArray(a);
