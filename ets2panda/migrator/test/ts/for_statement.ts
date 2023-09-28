/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

export function fun(): void {
    for (;;) break;

    for (;;) {
        break;
    }

    for (let i = 0 ; ; ) {
        i++;
        if (i == 5) continue;
        if (i == 10) break;
    }

    let a = 0;
    for ( ; a < 5 ; ) a++;

    for ( ; ; a--) {
        if (a <= 0) break;
    }

    for (let i = 0, j = 0, k = 0; i < 5; i++, j++, k++) {
        let q = i * j + k;
    }

    let b = 0, c = 0;
    for (a = 5, b = 5, c = 5; a >= 0; --a, --b, --c) {
        let d = a / b - c;
    }

    for (const x = 10; ; ) break;

    outerLoop:
    for (let i = 0; i < 10; i++) {
        innerLoop:
        for (let j = 0; j < 10; j++) {
            if (j == 5) continue innerLoop;
            if (i * j == 64) break outerLoop;
        }
    }
}
