/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

// We don't report errors that originated from *.d.ts files (i.e. from any external library)

import {
  InsightIntent,
  margin,
  WindowsStage,
  Indexed,
  TypeLiteral
} from "./d_ts.lib";

// issue 13041: Object literal
let intent: InsightIntent = { // OK
  intentEntityInfo: {
    entityId: '1',
    entityName: '2',
    prop1: '3',
    prop2: '4'
  }
}

// issue 13043: Object literal
margin<string>({ top: 24, bottom: 16 }); // OK

// issue 13048: Lambda parameter's omitted types
let windowStage: WindowsStage = new WindowsStage();
windowStage.loadContent('page/1', (err, data) => {}); // OK, lambda instantiates functional interface from the library, so parameter types may be omitted.
windowStage.loadContent2('page/1', (err, data) => {}); // OK, same as above

// Property indexed access
let idx1: Indexed = {
  a: 1,
  b: 2
}
idx1[1]; // OK
idx1['2']; // OK

interface Indexed2 {
  [x: string]: number;
}
let idx2: Indexed2 = { // CTE in ArkTS
  a: 1,
  b: 2
}
idx2[1]; // CTE in ArkTS
idx2['2']; // CTE in ArkTS

// initializing Type literal
let typeLiteral: TypeLiteral = { // OK
  a: 1,
  b: '2'
};

// Standard Library cases 
let aescbc: AesCbcParams = { // OK, object literal conforms the interface
  name: 'A',
  iv: { 
      buffer: new ArrayBuffer(0),
      byteLength: 1,
      byteOffset: 2
  }
};

let iterRes: IteratorResult<number> = { // OK, object literal conforms the interface
  value: 5
};

let obj: Object = { // CTE in ArkTS, Object can not be initialized with object literal
  a: 0
};