/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

abstract foo(1 > 0) { 
    console.log("hehe")
}


/* @@? 16:10 Error SyntaxError: abstract modifier can only appear on a class, struct, method, or property declaration.  */
/* @@? 16:13 Error SyntaxError: Unexpected token, expected: '{'.  */
/* @@? 16:16 Error SyntaxError: Unexpected token, expected: ';'.  */
/* @@? 16:19 Error SyntaxError: Unexpected token, expected: ';'.  */
/* @@? 16:21 Error SyntaxError: Unexpected token in class property  */