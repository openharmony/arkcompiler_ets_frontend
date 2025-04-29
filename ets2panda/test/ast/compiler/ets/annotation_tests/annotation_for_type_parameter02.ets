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
@interface Anno{}

let array1: Array<@Anno() Int> = new Array<@Anno() Int>()

class A{
   foo<T>(){}
   bar(){
      foo<@Anno T>()
      this.foo<@Anno T>()
   }
}

function foo<T>(){}
foo<@Anno T>()

/* @@? 17:27 Error SyntaxError: Annotations are not allowed on this type of declaration. */
/* @@? 17:52 Error SyntaxError: Annotations are not allowed on this type of declaration. */
/* @@? 22:17 Error SyntaxError: Annotations are not allowed on this type of declaration. */
/* @@? 22:17 Error TypeError: Cannot find type 'T'. */
/* @@? 23:22 Error SyntaxError: Annotations are not allowed on this type of declaration. */
/* @@? 23:22 Error TypeError: Cannot find type 'T'. */
/* @@? 28:11 Error SyntaxError: Annotations are not allowed on this type of declaration. */
/* @@? 28:11 Error TypeError: Cannot find type 'T'. */
