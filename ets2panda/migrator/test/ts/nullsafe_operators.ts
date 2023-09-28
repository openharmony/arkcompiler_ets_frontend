/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

function foo(x: string | null): string {
    return x ?? "";
}

function bar(action: () => void): void {
    action?.();
}

function goo(array: number[]): number {
    return array?.[0];
}

function zoo(s: string | null): number {
    return s?.length ?? 0;
}

function shmoo(s: string | null): string {
    return s! + "foo";
}

class C {
    s: string = "C";
}

function foobar(c?: C | null): string {
    return c?.["s"] ?? "";
}
