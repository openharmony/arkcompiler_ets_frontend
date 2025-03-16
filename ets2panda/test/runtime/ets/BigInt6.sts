/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

function test_plus(): void {
    assertEQ(new BigInt(10).operatorAdd(new BigInt(20)), 30n)
    assertEQ(new BigInt(1000).operatorAdd(new BigInt(10)), 1010n)
    assertEQ(new BigInt(-10).operatorAdd(new BigInt(9)), -1n)
    assertEQ(new BigInt(-10).operatorAdd(new BigInt(10)), 0n)
    assertEQ(new BigInt(-100).operatorAdd(new BigInt(10)), -90n)
    assertEQ(new BigInt(100).operatorAdd(new BigInt(10)), 110n)
    assertEQ(new BigInt(65535).operatorAdd(new BigInt(65535)) , 131070n)
    assertEQ(new BigInt(65500).operatorAdd(new BigInt(1)), (65501n))
    assertEQ(new BigInt(65500).operatorAdd(new BigInt(-1)), (65499n))
    assertEQ(new BigInt(-65500).operatorAdd(new BigInt(-1)), (-65501n))
    assertEQ(new BigInt(-65500).operatorAdd(new BigInt(1)), (-65499n))
    assertEQ(new BigInt(-65500).operatorAdd(new BigInt(100000)), (34500n))
    assertEQ(new BigInt(100).operatorAdd(new BigInt(0)), (100n))
    assertEQ(new BigInt(-100).operatorAdd(new BigInt(0)), (-100n))
    assertEQ(new BigInt(-10).operatorAdd(new BigInt(-10)), (-20n))
}

function test_addition_1(): void {
    const a = 97567789101304567800013210071n
    const b = -533923234343411557221n
    const c = 0n;

    /* Minus testing (-) */
    assertEQ(-a, -97567789101304567800013210071n)
    assertEQ(-b, 533923234343411557221n)
    assertEQ(-c, -0n)
    assertEQ(-(-a), a)
    assertEQ(-(-b), b)
    assertEQ(-(-c), c)

    /* Plus testing (+) */
    assertEQ(+a, a)
    assertEQ(+b, b)
    assertEQ(+c, 0n)
}

function test_addition_2(): void {
    const a = 18446744073709551616n;
    const b = 36893488147419103232n;
    const c = -10000000000000000000n;
    /* Addition testing (+) */
    assertEQ(999999999999999n + 1n, 1000000000000000n)
    assertEQ(a + b, 55340232221128654848n)
    assertEQ(a + a, b)
    assertEQ(a + c, 8446744073709551616n)
    assertEQ(a + b + b, 92233720368547758080n)
}

function main() {
    test_plus()
    test_addition_1()
    test_addition_2()
}
