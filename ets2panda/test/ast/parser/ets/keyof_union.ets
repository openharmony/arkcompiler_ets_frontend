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
  foo(){}
  private foo2(){}
}

function getProperty<K extends ((keyof A)|number|A)>(key: K){}

function main():void{
  let a:A = new A();

  type keyofA = keyof A;
  type keyofUnion = keyofA|number|A;
  let x1:keyofUnion = /* @@ label1 */"foo2";
  let x2:keyofUnion = /* @@ label2 */"other field";

  /* @@ label3 */getProperty<keyofA>(/* @@ label4 */"foo2")
  /* @@ label5 */getProperty<keyofA>(/* @@ label6 */"other field")
}

/* @@@ label1 Error TypeError: Type '"foo2"' cannot be assigned to type 'Double|A|"foo"|"field1"'  */
/* @@@ label2 Error TypeError: Type '"other field"' cannot be assigned to type 'Double|A|"foo"|"field1"'  */
/* @@@ label3 Error TypeError: No matching call signature for getProperty("foo2")  */
/* @@@ label4 Error TypeError: Type '"foo2"' is not compatible with type '"foo"|"field1"' at index 1  */
/* @@@ label5 Error TypeError: No matching call signature for getProperty("other field")  */
/* @@@ label6 Error TypeError: Type '"other field"' is not compatible with type '"foo"|"field1"' at index 1  */
