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

const sum1: ((...numbers: number[]) => number) = ((...numbers) => {
    return numbers.reduce<number>((a, b) => a + b, 0)
})

const sum2: ((n: int, ...numbers: number[]) => number) = ((n, ...numbers) => {
    return numbers.reduce<number>((a, b) => a + b, 0)
})

arktest.assertEQ(sum1(1,2,3,4), 10)
arktest.assertEQ(sum2(1,2,3,4), 9)
