/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

// test about variable captures
function foo(c: () => void): void {
    c();
}

function test_captures(): void {
    const num_const = 1
    let num = 2

    // capture in lambda
    foo() {
        assert num_const == 1: "expected: " + 1 + " actual: " + num_const;
        assert num == 2: "expected: " + 2 + " actual: " + num;
        {
            num++
            assert num_const == 1: "expected: " + 1 + " actual: " + num_const;
            assert num == 3: "expected: " + 3 + " actual: " + num;
        }

        let x: ()=>void = () => {
            num++  // This capture will cause crash issue(#I80K99)
        }
        x();

        if (true) {
            num++;
            assert num == 4: "expected: " + 4 + " actual: " + num;
            assert num_const == 1: "expected: " + 1 + " actual: " + num_const;
        }

        for (let i = 0; i < 2; ++i) {
            num++;
            assert num_const == 1: "expected: " + 1 + " actual: " + num_const;
        }

        assert num == 6: "expected: " + 6 + " actual: " + num;

        while (true) {
            if (num < 7) {
                num++
            } else {
                break;
            }
        }
        assert num == 7: "expected: " + 7 + " actual: " + num;

        foo() {
            num++;
            assert num == 8: "expected: " + 8 + " actual: " + num;
        }
    };
}

function main() {
    test_captures();
}
