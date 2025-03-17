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
    field1:int;
    field2:int;
    method1(){};
}

function foo(){}

function main():void{
    type UnionA = A|string|undefined
    type keyofUnion = keyof /* @@ label1 */unionA/* @@ label2 */;

    type keyofNever = keyof never/* @@ label3 */;

    type keyofFunction = keyof /* @@ label4 */foo/* @@ label5 */;

    type keyofVoid = keyof /* @@ label6 */void/* @@ label7 */;
}

/* @@@ label1 Error TypeError: Cannot find type 'unionA'.  */
/* @@@ label2 Error TypeError: The `keyof` keyword can only be used for class or interface type.  */
/* @@@ label3 Error TypeError: The `keyof` keyword can only be used for class or interface type.  */
/* @@@ label4 Error TypeError: Cannot find type 'foo'.  */
/* @@@ label5 Error TypeError: The `keyof` keyword can only be used for class or interface type.  */
/* @@@ label6 Error TypeError: 'void' used as type annotation.  */
/* @@@ label7 Error TypeError: The `keyof` keyword can only be used for class or interface type.  */
