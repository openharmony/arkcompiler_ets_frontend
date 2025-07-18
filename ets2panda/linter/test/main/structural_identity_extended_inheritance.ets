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

let arrBuf = new ArrayBuffer(1);
let arrBufView: ArrayBufferView = {buffer: arrBuf, byteLength: 1, byteOffset: 0};
let dataView = new DataView(arrBuf);
arrBufView = dataView;

let arrLike: ArrayLike<number> = [];
let arrLikeBigInt: ArrayLike<bigint> = [];
let float32Arr = new Float32Array(1);
let float64Arr = new Float64Array(1);
let int8Arr = new Int8Array(1);
let int16Arr = new Int16Array(1);
let int32Arr = new Int32Array(1);
let bigInt64Arr = new BigInt64Array(1);
let uint8ClampedArr = new Uint8ClampedArray(1);
let uint8Arr = new Uint8Array(1);
let uint16Arr = new Uint16Array(1);
let uint32Arr = new Uint32Array(1);
let bigUint64Arr = new BigUint64Array(1);

arrLike = float32Arr;
arrLike = float64Arr;
arrLike = int8Arr;
arrLike = int16Arr;
arrLike = int32Arr;
arrLikeBigInt = bigInt64Arr;
arrLike = uint8ClampedArr;
arrLike = uint8Arr;
arrLike = uint16Arr;
arrLike = uint32Arr;
arrLikeBigInt = bigUint64Arr;

let concatArr: ConcatArray<number> = [];
let readonlyArr: ReadonlyArray<number> = [];
let arr = new Array<number>();

arrLike = concatArr;
arrLike = readonlyArr;
arrLike = arr;
concatArr = readonlyArr;
concatArr = arr;
readonlyArr = arr;

let readonlyMap: ReadonlyMap<string, string>;
let map = new Map<string, string>();
let readonlySet: ReadonlySet<string>;
let set = new Set<string>();
readonlyMap = map;
readonlySet = set;

class C1 {
  a: number;
}
class C2<T> {
  a: T;
}
let c1 = new C1();
let c2 = new C2<number>();
c1 = c2; // ERROR
c2 = c1; // ERROR