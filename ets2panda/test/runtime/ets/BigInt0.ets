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

function test_create_empty_bigint(): void {
    let a = new BigInt()
    assertTrue(a.positive())
    assertEQ(a, 0n)

    let b = new BigInt()
    assertTrue(b.positive())
    assertEQ(b, 0n)
}

function test_invalid_bigint(): void {
    // NOTE(kkonsw): implement validation
}

function test_bigint_as_string(): void {
    assertEQ(new BigInt("10").toString(), "10")
    assertEQ(new BigInt("1000").toString(), "1000")
    assertEQ(new BigInt("-1000").toString(), "-1000")
    assertEQ(new BigInt("-1").toString(), "-1")
    assertEQ(new BigInt("-10").toString(), "-10")
    assertEQ(new BigInt("-100").toString(), "-100")
    assertEQ(new BigInt("-100000000000000").toString(), "-100000000000000")
    assertEQ(new BigInt("0").toString(), "0")
}

function test_type(): void {
    let num0 = 0n;
    let num1 = 100_100_100_100_100_100n
    let num2 = -57896044618658097711785492504343953926634992332820282019728792003956564819967n

    assertTrue(num0 instanceof bigint)
    assertTrue(num1 instanceof bigint)
    assertTrue(num2 instanceof bigint)
}

function test_assignment(): void {
    let a = -24059059045444224545405903904190343043049209420234290480n
    let b = a
    assertTrue(a instanceof bigint)
    assertTrue(b instanceof bigint)
    assertEQ(a, b)

    a = 123n;
    assertTrue(a instanceof bigint)
    assertEQ(a.toString(), "123")
    assertEQ(a, 123n)

    const zero = 0n;
    let c = zero;
    assertTrue(zero instanceof bigint)
    assertTrue(c instanceof bigint)
    assertEQ(zero, c)
}

function test_compare(): void {
    const a = 24400569094091093912039019089543850580328542852805043n
    const b = 34034240244909504590902901119302940942904944029040950n

    assertTrue(44493059209094029409209402940924902n < 140044940590459049067274048929058908989042385n)
    assertTrue(44493059209094029409209402940924902n < a)
    assertTrue(a < 34034240244909504590902901119302940942904944029040950n)
    assertTrue(a < b)

    assertTrue(44493059209094029409209402940924902n <= 140044940590459049067274048929058908989042385n)
    assertTrue(44493059209094029409209402940924902n <= a)
    assertTrue(a <= 34034240244909504590902901119302940942904944029040950n)
    assertTrue(a <= b)

    assertTrue(44493059209094029409209402940924902n <= 44493059209094029409209402940924902n)
    assertTrue(24400569094091093912039019089543850580328542852805043n <= a)
    assertTrue(a <= 24400569094091093912039019089543850580328542852805043n)
    assertTrue(a <= a)

    assertTrue(40044940590459049067274048929058908989042385n > 44493059209094029409209402940924902n)
    assertTrue(34034240244909504590902901119302940942904944029040950n > a)
    assertTrue(a > 140044940590459049067274048929058908989042385n)
    assertTrue(b > a)

    assertTrue(40044940590459049067274048929058908989042385n >= 44493059209094029409209402940924902n)
    assertTrue(34034240244909504590902901119302940942904944029040950n >= a)
    assertTrue(a >= 140044940590459049067274048929058908989042385n)
    assertTrue(b >= a)

    assertTrue(44493059209094029409209402940924902n <= 44493059209094029409209402940924902n)
    assertTrue(24400569094091093912039019089543850580328542852805043n <= a)
    assertTrue(a <= 24400569094091093912039019089543850580328542852805043n)
    assertTrue(a <= a)
}

function test_literals() : void {
    let num0 = 0n
    assertEQ(num0.toString(), "0")

    let num1 = 127n
    assertEQ(num1.toString(), "127")

    let num2 = 32767n
    assertEQ(num2.toString(), "32767")

    let num3 = 2147483647n
    assertEQ(num3.toString(), "2147483647")

    let num4 = 9223372036854775807n
    assertEQ(num4.toString(), "9223372036854775807")

    let num5 = 170141183460469231731687303715884105727n
    assertEQ(num5.toString(), "170141183460469231731687303715884105727")

    let num6 = 57896044618658097711785492504343953926634992332820282019728792003956564819967n
    assertEQ(num6.toString(), "57896044618658097711785492504343953926634992332820282019728792003956564819967")

    let num1_n = -128n
    assertEQ(num1_n.toString(), "-128")

    let num2_n = -32768n
    assertEQ(num2_n.toString(), "-32768")

    let num3_n = -2147483648n
    assertEQ(num3_n.toString(), "-2147483648")

    let num4_n = -9223372036854775808n
    assertEQ(num4_n.toString(), "-9223372036854775808")

    let num5_n = -170141183460469231731687303715884105728n
    assertEQ(num5_n.toString(), "-170141183460469231731687303715884105728")

    let num6_n = -57896044618658097711785492504343953926634992332820282019728792003956564819968n
    assertEQ(num6_n.toString(), "-57896044618658097711785492504343953926634992332820282019728792003956564819968")

    let num1_sep = 1_991_653_125_841_217_555_434419_9091_123000000_3_3313_5775_3282_29n
    assertEQ(num1_sep.toString(), "19916531258412175554344199091123000000333135775328229")

    let num2_sep = -422_12_3333_9844_3333_3443_34111_43434_1111_11_1_3_3_411909_990081n
    assertEQ(num2_sep.toString(), "-4221233339844333334433411143434111111133411909990081")

    let num0_t: bigint = 0n
    assertEQ(num0_t.toString(), "0")

    let num1_t: bigint = 57896044618658097711785492504343953926634992332820282019728792003956564819967n
    assertEQ(num1_t.toString(), "57896044618658097711785492504343953926634992332820282019728792003956564819967")

    let num2_t: bigint = -9223372036854775808n
    assertEQ(num2_t.toString(), "-9223372036854775808")

    let num3_t: bigint = 1_991_653_125_841_217_555_434419_9091_123000000_3_3313_5775_3282_29n
    assertEQ(num3_t.toString(), "19916531258412175554344199091123000000333135775328229")

    let num4_t: bigint = -422_12_3333_9844_3333_3443_34111_43434_1111_11_1_3_3_411909_990081n
    assertEQ(num4_t.toString(), "-4221233339844333334433411143434111111133411909990081")

    const num0_c = 0n
    assertEQ(num0_c.toString(), "0")

    const num1_c = 1267650600228229401496703205376n
    assertEQ(num1_c.toString(), "1267650600228229401496703205376")

    const num2_c = -1427247692705959881058285969449495136382746624n
    assertEQ(num2_c.toString(), "-1427247692705959881058285969449495136382746624")

    const num3_c = 4_000_000_000_000_000_000_000_100n
    assertEQ(num3_c.toString(), "4000000000000000000000100")

    const num4_c: bigint = -7777777_666666_55555_4444_333_22_1n
    assertEQ(num4_c.toString(), "-7777777666666555554444333221")
}

function test_cast(): void {
    const v = 1559053
    const b: byte = 44
    const s: short = -17600
    const i: int = 1150483640
    const l: long = -8223372036854775808

    // NOTE(kkonsw): casts currently do not work
}

function test_bigint_methods(): void {
    const b: byte = 44
    const s: short = -17600
    const i: int = 1150483640
    const l: long = -8223372036854775808

    /* Testing BigInt constructor */
    let n0 = new BigInt(0)
    assertEQ(n0, 0n)
    assertEQ(n0.toString(), "0")

    let n1 = new BigInt(654093)
    assertEQ(n1.toString(), "654093")
    assertEQ(n1, 654093n)

    let n2 = new BigInt(b)
    assertEQ(n2.toString(), "44")
    assertEQ(n2, 44n)

    let n3 = new BigInt(s)
    assertEQ(n3.toString(), "-17600")
    assertEQ(n3, -17600n)

    let n4 = new BigInt(i)
    assertEQ(n4.toString(), "1150483640")
    assertEQ(n4, 1150483640n)

    let n5 = new BigInt(l)
    assertEQ(n5.toString(), "-8223372036854775808")
    assertEQ(n5, -8223372036854775808n)

    let dec = new BigInt("-12392320390239294724747283477947923471101032")
    assertEQ(dec, -12392320390239294724747283477947923471101032n)

    const n7 = 12392320390239294724747283477947923471101032n

    /* Testing asIntN() static method */
    assertEQ(BigInt.asIntN(0, n7), 0n)
    assertEQ(BigInt.asIntN(8, n7), 104n)
    assertEQ(BigInt.asIntN(16, n7), 27752n)
    assertEQ(BigInt.asIntN(32, n7), -737317784n)
    assertEQ(BigInt.asIntN(64, n7), -7098331616643290008n)

    /* Testing asUintN() static method */
    assertEQ(BigInt.asUintN(0, n7), 0n)
    assertEQ(BigInt.asUintN(8, n7), 104n)
    assertEQ(BigInt.asUintN(16, n7), 27752n)
    assertEQ(BigInt.asUintN(32, n7), 3557649512n)
    assertEQ(BigInt.asUintN(64, n7), 11348412457066261608n)
}

function test_shift(): void {
    const a = 245599210405555256299145n
    /* Testing left shift (<<) */
    assertEQ(a << 100n, 311333986486181324779687697000809288883015536628203520n)
    assertEQ(a << 0n, a)

    /* Testing right shift (>>) */
    assertEQ(a >> 60n, 213023n)
    assertEQ(a >> 0n, a)
}

function test_scientific(): void {
    assertEQ(new BigInt(0.0e0).toString(), "0",  "BigInt(0.0e0)")
    assertEQ(new BigInt(0.0e+0).toString(), "0",  "BigInt(0.0e+0)")
    assertEQ(new BigInt(0.0e-0).toString(), "0",  "BigInt(0.0e-0).toString()")
    assertEQ(new BigInt(-0.0e0).toString(), "0",  "BigInt(-0.0e0).toString()")
    assertEQ(new BigInt(1e23).toString(), "100000000000000000000000",  "BigInt(1e22)")
    assertEQ(new BigInt(1e+23).toString(), "100000000000000000000000",  "BigInt(1e+22)")
    assertEQ(new BigInt(-1e23).toString(), "-100000000000000000000000",  "BigInt(-1e22)")
    assertEQ(new BigInt(-1e+23).toString(), "-100000000000000000000000",  "BigInt(-1e+22)")

    assertEQ(new BigInt(1.234567e10).toString(), "12345670000",  "BigInt(1.234567e10).toString()")
    assertEQ(new BigInt(1.234567e20).toString(), "123456700000000000000",  "BigInt(1.234567e20).toString()")

    assertEQ(new BigInt(1.2345678912e21).toString(), "1234567891200000000000",  "BigInt(1.2345678912e21)")
    assertEQ(new BigInt(1.2345678912e+21).toString(), "1234567891200000000000",  "BigInt(1.2345678912e+21)")
    assertEQ(new BigInt(-1.2345678912e21).toString(), "-1234567891200000000000",  "BigInt(-1.2345678912e21)")
}

function test_double(): void {
    let bigIntFromDouble = (x: number): boolean => {
        try {
            let b = new BigInt(x);
        } catch (e) {
            return e instanceof Error;
        }
        return false
    };

    assertTrue(bigIntFromDouble(0.1),  "BigInt(0.1)")
    assertTrue(bigIntFromDouble(-0.1),  "BigInt(-0.1)")
    assertTrue(bigIntFromDouble(42.1234567),  "BigInt(42.1234567)")
    assertTrue(bigIntFromDouble(1.234567e2),  "BigInt(1.234567e2)")
    assertTrue(bigIntFromDouble(1e-22),  "BigInt(1e-22)")
    assertTrue(bigIntFromDouble(-1e-22),  "BigInt(-1e-22)")
    assertTrue(bigIntFromDouble(1.88e-20),  "BigInt(1.88e-20)")
    assertTrue(bigIntFromDouble(1.2345678848e-21),  "BigInt(1.2345678484e-21)")
}

function test_sign(): void {
    assertEQ(new BigInt().negative()   , false ,  'BigInt() is negative')
    assertEQ(new BigInt(0).negative()   , false ,  'BigInt(0) is negative')
    assertEQ(new BigInt(-0).negative()  , false ,  'BigInt(-0) is negative')
    assertEQ(new BigInt(0.0).negative() , false ,  'BigInt(0.0) is negative')
    assertEQ(new BigInt(-0.0).negative(), false ,  'BigInt(-0.0) is negative')
    assertEQ(new BigInt("0").negative() , false ,  'BigInt("0") is negative')
    assertEQ(new BigInt("-0").negative(), false ,  'BigInt("-0") is negative')

    assertEQ(new BigInt().positive()    , true ,  'BigInt() is not positive')
    assertEQ(new BigInt(0).positive()   , true ,  'BigInt(0) is not positive')
    assertEQ(new BigInt(-0).positive()  , true ,  'BigInt(-0) is not positive')
    assertEQ(new BigInt(0.0).positive() , true ,  'BigInt(0.0) is not positive')
    assertEQ(new BigInt(-0.0).positive(), true ,  'BigInt(-0.0) is not positive')
    assertEQ(new BigInt("0").positive() , true ,  'BigInt("0") is not positive')
    assertEQ(new BigInt("-0").positive(), true ,  'BigInt("-0") is not positive')

    assertEQ(new BigInt("0").negate().positive() , true ,  'BigInt("0").negate() is not positive')
    assertEQ(new BigInt("-0").negate().positive(), true ,  'BigInt("-0").negate() is not positive')

    assertTrue((new BigInt("1")  + new BigInt("-1")).positive() ,  'BigInt(1 + -1) is not positive')
    assertTrue((new BigInt("-1") + new BigInt("1")).positive()  ,  'BigInt(-1 + 1) is not positive')
    assertTrue((new BigInt("1")  - new BigInt("1")).positive()  ,  'BigInt(1 - 1) is not positive')
    assertTrue((new BigInt("-1") - new BigInt("-1")).positive() ,  'BigInt(-1 - -1) is not positive')
    assertTrue((new BigInt("1")  * new BigInt("0")).positive()  ,  'BigInt(1 * 0) is not positive')
    assertTrue((new BigInt("-1") * new BigInt("0")).positive()  ,  'BigInt(-1 * 0) is not positive')
    assertTrue((new BigInt("0")  * new BigInt("1")).positive()  ,  'BigInt(0 * 1) is not positive')
    assertTrue((new BigInt("0")  * new BigInt("-1")).positive() ,  'BigInt(0 * -1) is not positive')
    assertTrue((new BigInt("0")  / new BigInt("1")).positive()  ,  'BigInt(0 / 1) is not positive')
    assertTrue((new BigInt("0")  / new BigInt("-1")).positive() ,  'BigInt(0 / -1) is not positive')
    assertTrue((new BigInt("4")  % new BigInt("2")).positive()  ,  'BigInt(4 % 2) is not positive')
    assertTrue((new BigInt("4")  % new BigInt("-2")).positive() ,  'BigInt(4 % -2) is not positive')
    assertTrue((new BigInt("-4") % new BigInt("2")).positive()  ,  'BigInt(-4 % 2) is not positive')
    assertTrue((new BigInt("-4") % new BigInt("-2")).positive() ,  'BigInt(-4 % -2) is not positive')
}

function main() : void {
    test_create_empty_bigint();
    test_bigint_as_string();
    test_invalid_bigint();
    test_type();
    test_assignment();
    test_compare();
    test_literals();
    test_cast();
    test_bigint_methods();
    test_shift();
    test_double();
    test_sign();
    // NOTE(aakmaev): Enable after fix #17683.
    // test_scientific();
}
