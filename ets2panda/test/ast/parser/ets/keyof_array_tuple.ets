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

class A{
  field1:number = 10;
  private field2:number = 20;
  foo(){}
}

function main():void{
  let a:A = new A();
  type keyofA = keyof A;

  let x1:("abcd"|keyofA|number|A)[] = ["abcd",/* @@ label1 */"field2","foo",123,a];
  let x2:("abcd"|keyofA|number|A)[] = ["abcd",/* @@ label2 */"other field","foo",123,a];

  let x3:["abcd",keyofA,number,A] = ["abcd",/* @@ label3 */"field2",123,a];
  let x4:["abcd",keyofA,number,A] = ["abcd",/* @@ label4 */"other field",123,a];

  let x5:Array<"abcd"|keyofA|number|A> = /* @@ label5 */new Array<"abcd"|keyofA|number|A>("abcd","field2","foo",123,a);
  let x6:Array<"abcd"|keyofA|number|A> = /* @@ label6 */new Array<"abcd"|keyofA|number|A>("abcd","other field","foo",123,a);
}

/* @@@ label1 Error TypeError: Array element at index 1 with type '"field2"' is not compatible with the target array element type '"abcd"|Double|A|"foo"|"field1"'  */
/* @@@ label2 Error TypeError: Array element at index 1 with type '"other field"' is not compatible with the target array element type '"abcd"|Double|A|"foo"|"field1"'  */
/* @@@ label3 Error TypeError: Array initializer's type is not assignable to tuple type at index: 1  */
/* @@@ label4 Error TypeError: Array initializer's type is not assignable to tuple type at index: 1  */
/* @@@ label5 Error TypeError: No matching construct signature for escompat.Array("abcd", "field2", "foo", int, A)  */
/* @@@ label6 Error TypeError: No matching construct signature for escompat.Array("abcd", "other field", "foo", int, A)  */
