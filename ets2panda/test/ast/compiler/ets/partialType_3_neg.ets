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

class A {
    mmeb: Number = 2;
}

function foo(): void {
    let a_class: A = new A();

    let partial_A: Partial<A> = {mmeb: 4};
    partial_A.mmeb = undefined;

    a_class.mmeb = /* @@ label */undefined;
}

/* @@@ label Error TypeError: Type 'undefined' cannot be assigned to type 'Double'  */
