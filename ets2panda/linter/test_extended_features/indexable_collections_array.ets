/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable low or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import collections from './@arkts.collections';

let array1: collections.Array<number> = new collections.Array<number>();
let set1: collections.Set<number> = new collections.Set<number>();
let map1: collections.Map<number, number> = new collections.Map<number, number>();

console.log(array1[0]); // Legal
const num = 123;
console.log(array1[num]); // Legal

console.log(array1['str']); // Illegal
const str = 'abc';
console.log(array1[str]); // Illegal

console.log(set1[0]); // Illegal

console.log(map1[0]); //Illegal

let int8arr: collections.Int8Array = new collections.Int8Array(10);
let uint8arr: collections.Uint8Array = new collections.Uint8Array(10);
let uint8clampedarr: collections.Uint8ClampedArray = new collections.Uint8ClampedArray(10);
let int16arr: collections.Int16Array = new collections.Int16Array(10);
let uint16arr: collections.Uint16Array = new collections.Uint16Array(10);
let int32arr: collections.Int32Array = new collections.Int32Array(10);
let uint32arr: collections.Uint32Array = new collections.Uint32Array(10);
let bitVector: collections.BitVector = new collection.BitVector(10);

console.log(int8arr[0]); // Legal
console.log(uint8arr[0]); // Legal
console.log(uint8clampedarr[0]); // legal
console.log(int16arr[0]); // Legal
console.log(uint16arr[0]); // Legal
console.log(int32arr[0]); // Legal
console.log(uint32arr[0]); // Legal
console.log(bitVector[0]); // Legal
console.log(int8arr[num]); // Legal
console.log(uint8arr[num]); // Legal
console.log(uint8clampedarr[num]); // legal
console.log(int16arr[num]); // Legal
console.log(uint16arr[num]); // Legal
console.log(int32arr[num]); // Legal
console.log(uint32arr[num]); // Legal
console.log(bitVector[num]); // Legal

console.log(int8arr['str']); // Illegal
console.log(uint8arr['str']); // Illegal
console.log(uint8clampedarr['str']); // Illegal
console.log(int16arr['str']); // Illegal
console.log(uint16arr['str']); // Illegal
console.log(int32arr['str']); // Illegal
console.log(uint32arr['str']); // Illegal
console.log(bitVector['str']); // Illegal
console.log(int8arr[str]); // Illegal
console.log(uint8arr[str]); // Illegal
console.log(uint8clampedarr[str]); // Illegal
console.log(int16arr[str]); // Illegal
console.log(uint16arr[str]); // Illegal
console.log(int32arr[str]); // Illegal
console.log(uint32arr[str]); // Illegal
console.log(bitVector['str']); // Illegal
