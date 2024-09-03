/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

class A{}

function main(): void {
  ClassEquality();
  NullEquality();
  ArrayEquality();
}

function ClassEquality(): void {
    let a : A = new A();
    let b = a;
    assert (a === b);
    let c : A = new A();
    assert (a !== c);
}


function NullEquality(): void {
    let a : A | null = null;
    let b = a;
    assert (a === b);
    let c : A | null = null;
    assert (c === null);
    assert (null === null);
}


function ArrayEquality(): void {
    let a : int[] = [1, 2, 3];
    let b = a;
    assert (a === b);
    let c : int[] = [1, 2, 3];
    assert (a !== c);
}

function NumericEquality(): void {
    let a : Int = 1;
    let b = a;
    assert (a === b);
    let c : Int = 1;
    assert (a !== c);
    let d : Double = 1.0;
    assert (a !== c);
}
