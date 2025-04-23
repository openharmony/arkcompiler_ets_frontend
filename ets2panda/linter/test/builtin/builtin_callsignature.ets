/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

function createArray(ctor: ArrayConstructor) {
  return ctor<number>(1, 2, 3);
}
function createArrayDirect() {
  return Array<number>(1, 2, 3)
}

function createBigInt(ctor: BigIntConstructor) {
  return ctor(1);
}
function createBigIntDirect() {
  return BigInt(1);
}

function anotherName(ctorName0: BigIntConstructor) {
  ctorName0(1);
  const ctorName1 = ctorName0
  const rs1 = ctorName1(1);
  type BigIntConstructor1 = BigIntConstructor;
  let ctorName2:BigIntConstructor1 = ctorName1
  const rs2 = ctorName2(1);
}