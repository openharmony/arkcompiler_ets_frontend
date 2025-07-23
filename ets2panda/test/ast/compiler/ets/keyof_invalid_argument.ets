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

function foo<T>(t: T | {}, k: keyof (T | {})) {}

class ObservableImpl<T> extends Observable<T> {
  extendObservable<U extends object>(extraProps: U) {
    new ObservableImpl<{ [K in keyof (T & U)]: (T & U)[K] }>();
 }
}

type NestedKey<T, K extends keyof T> = T[K] extends object ? keyof T[K] : never;

/* @@? 16:24 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 16:24 Error SyntaxError: Invalid Type. */
/* @@? 16:26 Error SyntaxError: Unexpected token ','. */
/* @@? 16:28 Error SyntaxError: Unexpected token 'k'. */
/* @@? 16:31 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 16:31 Error TypeError: Unresolved reference keyof */
/* @@? 16:42 Error SyntaxError: Invalid Type. */
/* @@? 16:42 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 16:45 Error SyntaxError: Unexpected token ')'. */
/* @@? 16:47 Error SyntaxError: Unexpected token '{'. */
/* @@? 18:33 Error TypeError: Cannot find type 'Observable'. */
/* @@? 18:33 Error TypeError: The super type of 'ObservableImpl' class is not extensible. */
/* @@? 20:9 Error TypeError: Type 'ObservableImpl<T>' is generic but type argument were not provided. */
/* @@? 20:24 Error SyntaxError: Invalid Type. */
/* @@? 20:24 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 20:27 Error TypeError: Unresolved reference K */
/* @@? 20:29 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 20:29 Error SyntaxError: Unexpected token 'in'. */
/* @@? 20:29 Error TypeError: Unresolved reference in */
/* @@? 20:32 Error SyntaxError: Unexpected token 'keyof'. */
/* @@? 20:32 Error TypeError: This expression is not callable. */
/* @@? 20:41 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 20:45 Error SyntaxError: Unexpected token ']'. */
/* @@? 20:46 Error SyntaxError: Unexpected token ':'. */
/* @@? 20:46 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 20:60 Error SyntaxError: Unexpected token '>'. */
/* @@? 20:61 Error SyntaxError: Unexpected token '('. */
/* @@? 20:62 Error SyntaxError: Unexpected token ')'. */
/* @@? 22:1 Error SyntaxError: Unexpected token '}'. */
/* @@? 24:36 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 24:42 Error SyntaxError: Unexpected token ']'. */
/* @@? 24:42 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 24:43 Error SyntaxError: Unexpected token ']'. */
/* @@? 24:45 Error SyntaxError: Unexpected token 'extends'. */
/* @@? 24:53 Error SyntaxError: Unexpected token 'object'. */
/* @@? 24:53 Error TypeError: Type name 'object' used in the wrong context */
/* @@? 24:68 Error SyntaxError: Unexpected token. */
/* @@? 24:68 Error TypeError: Unresolved reference T */
/* @@? 24:68 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 24:70 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 24:73 Error SyntaxError: Unexpected token ':'. */
/* @@? 24:75 Error SyntaxError: Unexpected token 'never'. */
/* @@? 24:75 Error TypeError: Class name 'never' used in the wrong context */
