/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

let a = Symbol.asyncIterator;
let b = Symbol.hasInstance;
let c = Symbol.isConcatSpreadable;
let d = Symbol.iterator;
let e = Symbol.match;
let f = Symbol.replace;
let g = Symbol.search;
let h = Symbol.species;
let i = Symbol.split;
let j = Symbol.toPrimitive;
let k = Symbol.toStringTag;
let l = Symbol.unscopables;

let m = Symbol();

const sc = Symbol();

let id = Symbol.for("item");

let lambda = () => Symbol();

class TestClass {
  static readonly symStaticField: Symbol = Symbol();
  private symField = Symbol();

  static staticSymbolMethod() {
    let sv = Symbol();
  }

  symbolMethod() {
    let sv = Symbol();
  }

  methodRet(): Symbol {
    return Symbol();
  }
}

class BIter  {
  [Symbol.iterator] = () => {
    return 1;
  };
}
