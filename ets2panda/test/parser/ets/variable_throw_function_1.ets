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

function foo() : void {}

function bar() : void throws {}

function baz(e: () => void throws) : void rethrows {}

function main(): void {
    let throwing1: () => void throws = foo;
    
    let throwing2: () => void throws = bar;
    
    let throwing3: (e: () => void throws) => void throws = baz;
}
