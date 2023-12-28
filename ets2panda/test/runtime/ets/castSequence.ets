/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

function main(): void {
  let a_int : int = 2147;
  let b_Num : Number = a_int as Number;

  assert b_Num instanceof Number && b_Num.unboxed() == 2147.0

  let a_Short : Short = 215;
  let b_double : double = a_Short as double;

  assert a_Short instanceof Short
  assert b_double == 215.0

  let a_Int : Int = 2142;
  let b_Double : Double = a_Int as Double;

  assert b_Double instanceof Double && b_Double.unboxed() == 2142.0

  return;
}