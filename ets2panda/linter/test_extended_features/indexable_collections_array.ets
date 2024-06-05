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

console.log(array1[0]); // Legal
const num = 123;
console.log(array1[num]); // Legal

console.log(array1['str']); // Illegal
const str = "abc";
console.log(array1[str]); // Illegal

console.log(set1[0]); // Illegal

let int8arr = new collections.Int8Array(10);
let uint8arr = new collections.Uint8Array(10);
let uint8clampedarr = new collections.Uint8ClampedArray(10);
let int16arr = new collections.Int16Array(10);
let uint16arr = new collections.Uint16Array(10);
let int32arr = new collections.Int32Array(10);
let uint32arr = new collections.Uint32Array(10);
let float32arr = new collections.Float32Array(10);
let float64arr = new collections.Float64Array(10);
let bigint64arr = new collections.BigInt64Array(10);
let biguint64arr = new collections.BigUint64Array(10);

console.log(int8arr[0]); // Legal
console.log(uint8arr[0]); // Legal
console.log(uint8clampedarr[0]); // Illegal
console.log(int16arr[0]); // Legal
console.log(uint16arr[0]); // Legal
console.log(int32arr[0]); // Legal
console.log(uint32arr[0]); // Legal
console.log(float32arr[0]); // Illegal
console.log(float64arr[0]); // Illegal
console.log(bigint64arr[0]); // Illegal
console.log(biguint64arr[0]); // Illegal
console.log(int8arr[num]); // Legal
console.log(uint8arr[num]); // Legal
console.log(uint8clampedarr[num]); // Illegal
console.log(int16arr[num]); // Legal
console.log(uint16arr[num]); // Legal
console.log(int32arr[num]); // Legal
console.log(uint32arr[num]); // Legal
console.log(float32arr[num]); // Illegal
console.log(float64arr[num]); // Illegal
console.log(bigint64arr[num]); // Illegal
console.log(biguint64arr[num]); // Illegal

console.log(int8arr['str']); // Illegal
console.log(uint8arr['str']); // Illegal
console.log(uint8clampedarr['str']); // Illegal
console.log(int16arr['str']); // Illegal
console.log(uint16arr['str']); // Illegal
console.log(int32arr['str']); // Illegal
console.log(uint32arr['str']); // Illegal
console.log(float32arr['str']); // Illegal
console.log(float64arr['str']); // Illegal
console.log(bigint64arr['str']); // Illegal
console.log(biguint64arr['str']); // Illegal
console.log(int8arr[str]); // Illegal
console.log(uint8arr[str]); // Illegal
console.log(uint8clampedarr[str]); // Illegal
console.log(int16arr[str]); // Illegal
console.log(uint16arr[str]); // Illegal
console.log(int32arr[str]); // Illegal
console.log(uint32arr[str]); // Illegal
console.log(float32arr[str]); // Illegal
console.log(float64arr[str]); // Illegal
console.log(bigint64arr[str]); // Illegal
console.log(biguint64arr[str]); // Illegal
