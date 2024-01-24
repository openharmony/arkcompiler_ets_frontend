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

function test_bitwise_and(): void {
    assert new BigInt("10").operatorBitwiseAnd(new BigInt("2")).toString().equals("2");
    assert new BigInt("256").operatorBitwiseAnd(new BigInt("1")).toString().equals("0");
    assert new BigInt("3124378143267041203423").operatorBitwiseAnd(new BigInt("43621978")).toString().equals("41948250");
    assert new BigInt("256").operatorBitwiseAnd(new BigInt("256")).toString().equals("256");
    assert new BigInt("12345678").operatorBitwiseAnd(new BigInt("1234")).toString().equals("66");
}

function test_bitwise_or(): void {
    assert new BigInt("10").operatorBitwiseOr(new BigInt("2")).toString().equals("10");
    assert new BigInt("256").operatorBitwiseOr(new BigInt("1")).toString().equals("257");
    assert new BigInt("256").operatorBitwiseOr(new BigInt("256")).toString().equals("256");
    assert new BigInt("3124378143267041203423").operatorBitwiseOr(new BigInt("43621978")).toString().equals("3124378143267042877151");
    assert new BigInt("12345678").operatorBitwiseOr(new BigInt("1234")).toString().equals("12346846");
}

function test_bitwise_xor(): void {
    assert new BigInt("10").operatorBitwiseXor(new BigInt("2")).toString().equals("8");
    assert new BigInt("256").operatorBitwiseXor(new BigInt("1")).toString().equals("257");
    assert new BigInt("256").operatorBitwiseXor(new BigInt("256")).toString().equals("0");
    assert new BigInt("3124378143267041203423").operatorBitwiseXor(new BigInt("43621978")).toString().equals("3124378143267000928901");
    assert new BigInt("12345678").operatorBitwiseXor(new BigInt("1234")).toString().equals("12346780");
}

function test_left_shift(): void {
    assert new BigInt("0").operatorLeftShift(new BigInt("0")).toString().equals("0");
    assert new BigInt("0").operatorLeftShift(new BigInt("1")).toString().equals("0");
    assert new BigInt("1").operatorLeftShift(new BigInt("0")).toString().equals("1");
    assert new BigInt("10").operatorLeftShift(new BigInt("2")).toString().equals("40");
    assert new BigInt("255").operatorLeftShift(new BigInt("41")).toString().equals("560750930165760");
    assert new BigInt("65535").operatorLeftShift(new BigInt("60")).toString().equals("75556710804409716572160");
    assert new BigInt("4294967295").operatorLeftShift(new BigInt("5")).toString().equals("137438953440");
    assert new BigInt("18446744073709551615").operatorLeftShift(new BigInt("6")).toString().equals("1180591620717411303360");
    assert new BigInt("1275418875248948586535904902545412130").operatorLeftShift(new BigInt("123")).toString().equals("13562579802667292602585801202159372574330573695725523059072421474640855040");
    assert new BigInt("2").operatorLeftShift(new BigInt("218")).toString().equals("842498333348457493583344221469363458551160763204392890034487820288");
    assert new BigInt("-1").operatorLeftShift(new BigInt("0")).toString().equals("-1");
    assert new BigInt("-12").operatorLeftShift(new BigInt("4")).toString().equals("-192");
    assert new BigInt("-255").operatorLeftShift(new BigInt("19")).toString().equals("-133693440");
    assert new BigInt("-65535").operatorLeftShift(new BigInt("73")).toString().equals("-618960574909724398159134720");
    assert new BigInt("-4294967295").operatorLeftShift(new BigInt("24")).toString().equals("-72057594021150720");
    assert new BigInt("-18446744073709551615").operatorLeftShift(new BigInt("31")).toString().equals("-39614081257132168794624491520");
    assert new BigInt("-4095059032950818422890113130149234924134").operatorLeftShift(new BigInt("103")).toString().equals("-41528832328721100931613913139905162112381494314462183326283215847555072");
}

function test_right_shift(): void {
    assert new BigInt("-200").operatorRightShift(new BigInt("2")).toString().equals("-50");
    assert new BigInt("-12").operatorRightShift(new BigInt("2")).toString().equals("-3");
    assert new BigInt("-1").operatorRightShift(new BigInt("0")).toString().equals("-1");
    assert new BigInt("0").operatorRightShift(new BigInt("0")).toString().equals("0");
    assert new BigInt("0").operatorRightShift(new BigInt("1")).toString().equals("0");
    assert new BigInt("1").operatorRightShift(new BigInt("0")).toString().equals("1");
    assert new BigInt("55").operatorRightShift(new BigInt("2")).toString().equals("13");
    assert new BigInt("-50").operatorRightShift(new BigInt("2")).toString().equals("-13");
    assert new BigInt("255").operatorRightShift(new BigInt("4")).toString().equals("15");
    assert new BigInt("255").operatorRightShift(new BigInt("8")).toString().equals("0");
    assert new BigInt("65535").operatorRightShift(new BigInt("10")).toString().equals("63");
    assert new BigInt("4294967295").operatorRightShift(new BigInt("17")).toString().equals("32767");
    assert new BigInt("4294967295").operatorRightShift(new BigInt("48")).toString().equals("0");
    assert new BigInt("18446744073709551615").operatorRightShift(new BigInt("55")).toString().equals("511");
    assert new BigInt("4930493049034092989191918392837727383823827").operatorRightShift(new BigInt("129")).toString().equals("7244");
    assert new BigInt("34930693049034092980065918370009389341341932481328231493102392100010239").operatorRightShift(new BigInt("41")).toString().equals("15884640128676479880626138024130973163365493965706369405371");
    assert new BigInt("34095405903900293499034024029409200000000000000000000094049304394284993939382949384984981018480144184891848991934893429489324901148449849382222222222222888384932890000103010381803018300103180381030084545225875678328499213403403984398439489384984287113383827387373382328328194394892948392222219791749717949183748237").operatorRightShift(new BigInt("511")).toString().equals("5085903091997271218878067997324523590835536101241386224503069830700984460490307918626942225457432781938207872710051592009243523341752202627425621983245162030428");
    assert new BigInt("-255").operatorRightShift(new BigInt("2")).toString().equals("-64");
    assert new BigInt("-65535").operatorRightShift(new BigInt("12")).toString().equals("-16");
    assert new BigInt("-4294967295").operatorRightShift(new BigInt("18")).toString().equals("-16384");
    assert new BigInt("-18446744073709551615").operatorRightShift(new BigInt("38")).toString().equals("-67108864");
    assert new BigInt("-4095059032950818422890113130149234924134").operatorRightShift(new BigInt("99")).toString().equals("-6460863952");
    assert new BigInt("-3294302940940294094923040592059302590950294502940294029029409029429042942049028100104029439420990952").operatorRightShift(new BigInt("100")).toString().equals("-2598746800062401791237527125433630339355687972972274247737341685088307");
}

function test_module(): void {
    assert new BigInt("10").operatorModule(new BigInt("3")).toString().equals("1");
    assert new BigInt("10").operatorModule(new BigInt("-3")).toString().equals("1");
    assert new BigInt("-10").operatorModule(new BigInt("3")).toString().equals("-1");
    assert new BigInt("-10").operatorModule(new BigInt("-3")).toString().equals("-1");
    assert new BigInt("100").operatorModule(new BigInt("50")).toString().equals("0");
    assert new BigInt("100").operatorModule(new BigInt("-50")).toString().equals("0");
    assert new BigInt("-100").operatorModule(new BigInt("50")).toString().equals("0");
    assert new BigInt("-100").operatorModule(new BigInt("-50")).toString().equals("0");
    assert new BigInt("3124378143267041203423").operatorModule(new BigInt("43621978")).toString().equals("18802883");
    assert new BigInt("-3124378143267041203423").operatorModule(new BigInt("43621978")).toString().equals("-18802883");
    assert new BigInt("3124378143267041203423").operatorModule(new BigInt("-43621978")).toString().equals("18802883");
    assert new BigInt("-3124378143267041203423").operatorModule(new BigInt("-43621978")).toString().equals("-18802883");
    assert new BigInt("100").operatorModule(new BigInt("250")).toString().equals("100");
    assert new BigInt("-100").operatorModule(new BigInt("250")).toString().equals("-100");
    assert new BigInt("100").operatorModule(new BigInt("-250")).toString().equals("100");
    assert new BigInt("-100").operatorModule(new BigInt("-250")).toString().equals("-100");
    assert new BigInt("0").operatorModule(new BigInt("8")).toString().equals("0");
}

function test_divide(): void {
    assert new BigInt("10").operatorDivide(new BigInt("3")).toString().equals("3");
    assert new BigInt("-10").operatorDivide(new BigInt("3")).toString().equals("-3");
    assert new BigInt("10").operatorDivide(new BigInt("-3")).toString().equals("-3");
    assert new BigInt("-10").operatorDivide(new BigInt("-3")).toString().equals("3");
    assert new BigInt("100").operatorDivide(new BigInt("50")).toString().equals("2");
    assert new BigInt("100").operatorDivide(new BigInt("-50")).toString().equals("-2");
    assert new BigInt("-100").operatorDivide(new BigInt("50")).toString().equals("-2");
    assert new BigInt("-100").operatorDivide(new BigInt("-50")).toString().equals("2");
    assert new BigInt("3124378143267041203423").operatorDivide(new BigInt("43621978")).toString().equals("71623944775430");
    assert new BigInt("-3124378143267041203423").operatorDivide(new BigInt("43621978")).toString().equals("-71623944775430");
    assert new BigInt("3124378143267041203423").operatorDivide(new BigInt("-43621978")).toString().equals("-71623944775430");
    assert new BigInt("-3124378143267041203423").operatorDivide(new BigInt("-43621978")).toString().equals("71623944775430");
    assert new BigInt("100").operatorDivide(new BigInt("250")).toString().equals("0");
    assert new BigInt("100").operatorDivide(new BigInt("-250")).toString().equals("0");
    assert new BigInt("-100").operatorDivide(new BigInt("250")).toString().equals("0");
    assert new BigInt("-100").operatorDivide(new BigInt("-250")).toString().equals("0");
    assert new BigInt("65000").operatorDivide(new BigInt("100")).toString().equals("650");
    assert new BigInt("65000").operatorDivide(new BigInt("-100")).toString().equals("-650");
    assert new BigInt("-65000").operatorDivide(new BigInt("100")).toString().equals("-650");
    assert new BigInt("-65000").operatorDivide(new BigInt("-100")).toString().equals("650");
}

function test_unary_minus(): void {
    assert new BigInt("10").negate().toString().equals("-10");
    assert new BigInt("1000").negate().toString().equals("-1000");
    assert new BigInt("-1").negate().toString().equals("1");
    assert new BigInt("-10").negate().toString().equals("10");
    assert new BigInt("-100").negate().toString().equals("100");
    assert new BigInt("0").negate().toString().equals("0");
}

function test_plus(): void {
    assert new BigInt("10").operatorAdd(new BigInt("20")).toString() == "30";
    assert new BigInt("1000").operatorAdd(new BigInt("10")).toString() == "1010";
    assert new BigInt("-10").operatorAdd(new BigInt("9")).toString() == "-1";
    assert new BigInt("-10").operatorAdd(new BigInt("10")).toString() == "0";
    assert new BigInt("-100").operatorAdd(new BigInt("10")).toString() == "-90";
    assert new BigInt("100").operatorAdd(new BigInt("10")).toString() == "110";
    assert new BigInt("65535").operatorAdd(new BigInt("65535")).toString() == "131070";
    assert new BigInt("65500").operatorAdd(new BigInt("1")).toString().equals("65501");
    assert new BigInt("65500").operatorAdd(new BigInt("-1")).toString().equals("65499");
    assert new BigInt("-65500").operatorAdd(new BigInt("-1")).toString().equals("-65501");
    assert new BigInt("-65500").operatorAdd(new BigInt("1")).toString().equals("-65499");
    assert new BigInt("-65500").operatorAdd(new BigInt("100000")).toString().equals("34500");
    assert new BigInt("100").operatorAdd(new BigInt("0")).toString().equals("100");
    assert new BigInt("-100").operatorAdd(new BigInt("0")).toString().equals("-100");
    assert new BigInt("-10").operatorAdd(new BigInt("-10")).toString().equals("-20");
}

function test_minus(): void {
    assert new BigInt("10").operatorSubtract(new BigInt("2")).toString().equals("8");
    assert new BigInt("2").operatorSubtract(new BigInt("10")).toString().equals("-8");
    assert new BigInt("-10").operatorSubtract(new BigInt("-2")).toString().equals("-8");
    assert new BigInt("-100").operatorSubtract(new BigInt("1")).toString().equals("-101");
    assert new BigInt("-100").operatorSubtract(new BigInt("-1")).toString().equals("-99");
    assert new BigInt("-1000").operatorSubtract(new BigInt("10")).toString().equals("-1010");
    assert new BigInt("1237840127434312471243").operatorSubtract(new BigInt("234112342314526914672342143621463921469")).toString().equals("-234112342314526913434502016187151450226");
    assert new BigInt("-1237840127434312471243").operatorSubtract(new BigInt("234112342314526914672342143621463921469")).toString().equals("-234112342314526915910182271055776392712");
    assert new BigInt("1237840127434312471243").operatorSubtract(new BigInt("-234112342314526914672342143621463921469")).toString().equals("234112342314526915910182271055776392712");
    assert new BigInt("-1237840127434312471243").operatorSubtract(new BigInt("-234112342314526914672342143621463921469")).toString().equals("234112342314526913434502016187151450226");
    assert new BigInt("-1000").operatorSubtract(new BigInt("-10")).toString().equals("-990");
    assert new BigInt("-100").operatorSubtract(new BigInt("0")).toString().equals("-100");
    assert new BigInt("0").operatorSubtract(new BigInt("-100")).toString().equals("100");
    assert new BigInt("0").operatorSubtract(new BigInt("100")).toString().equals("-100");
    assert new BigInt("65500").operatorSubtract(new BigInt("1")).toString().equals("65499");
    assert new BigInt("65500").operatorSubtract(new BigInt("-1")).toString().equals("65501");
    assert new BigInt("-65500").operatorSubtract(new BigInt("-1")).toString().equals("-65499");
    assert new BigInt("-65500").operatorSubtract(new BigInt("1")).toString().equals("-65501");
    assert new BigInt("65500").operatorSubtract(new BigInt("100000")).toString().equals("-34500");
    assert new BigInt("49798775").operatorSubtract(new BigInt("43621978")).toString().equals("6176797");
    assert new BigInt("10").operatorSubtract(new BigInt("20")).toString().equals("-10");
}

function test_multiply(): void {
    assert new BigInt("10").operatorMultiply(new BigInt("10")).toString() == "100";
    assert new BigInt("0").operatorMultiply(new BigInt("50")).toString() == "0";
    assert new BigInt("1").operatorMultiply(new BigInt("50")).toString() == "50";
    assert new BigInt("50").operatorMultiply(new BigInt("5")).toString() == "250";
    assert new BigInt("50").operatorMultiply(new BigInt("-5")).toString() == "-250";
    assert new BigInt("-1").operatorMultiply(new BigInt("-5")).toString() == "5";
    assert new BigInt("0").operatorMultiply(new BigInt("0")).toString() == "0";
    assert new BigInt("123").operatorMultiply(new BigInt("1")).toString() == "123";
    assert new BigInt("1234").operatorMultiply(new BigInt("987")).toString() == "1217958";
    assert new BigInt("3241847031247230147213740214703214721047312").operatorMultiply(new BigInt("412343124123421347812304712431421204731024")).toString() == "1336753332794721625246945391107220242430725631478413717131017736872102322242538207488";
    assert new BigInt("-3241847031247230147213740214703214721047312").operatorMultiply(new BigInt("-412343124123421347812304712431421204731024")).toString() == "1336753332794721625246945391107220242430725631478413717131017736872102322242538207488";
    assert new BigInt("-3241847031247230147213740214703214721047312").operatorMultiply(new BigInt("412343124123421347812304712431421204731024")).toString() == "-1336753332794721625246945391107220242430725631478413717131017736872102322242538207488";
    assert new BigInt("3241847031247230147213740214703214721047312").operatorMultiply(new BigInt("-412343124123421347812304712431421204731024")).toString() == "-1336753332794721625246945391107220242430725631478413717131017736872102322242538207488";
    assert new BigInt("256").operatorMultiply(new BigInt("256")).toString() == "65536";
}

function test_create_empty_bigint(): void {
    let a = new BigInt()
    assert a.positive()
    assert a.toString() == "0"

    let b = new BigInt("")
    assert b.positive()
    assert b.toString() == "0"
}

function test_invalid_bigint(): void {
    // NOTE(kkonsw): implement validation
}

function test_bigint_as_string(): void {
    assert new BigInt("10").toString() == "10"
    assert new BigInt("1000").toString() == "1000"
    assert new BigInt("-1000").toString() == "-1000"
    assert new BigInt("-1").toString() == "-1"
    assert new BigInt("-10").toString() == "-10"
    assert new BigInt("-100").toString() == "-100"
    assert new BigInt("-100000000000000").toString() == "-100000000000000"
    assert new BigInt("0").toString() == "0"
}

function test_type(): void {
    let num0 = 0n;
    let num1 = 100_100_100_100_100_100n
    let num2 = -57896044618658097711785492504343953926634992332820282019728792003956564819967n

    assert (num0 instanceof bigint)
    assert (num1 instanceof bigint)
    assert (num2 instanceof bigint)
}

function test_assignment(): void {
    let a = -24059059045444224545405903904190343043049209420234290480n
    let b = a
    assert (a instanceof bigint)
    assert (b instanceof bigint)
    assert (a.toString() == b.toString());

    a = 123n;
    assert (a instanceof bigint)
    assert (a.toString() == "123");
    assert (a == 123n);

    const zero = 0n;
    let c = zero;
    assert (zero instanceof bigint)
    assert (c instanceof bigint)
    assert (zero.toString() == c.toString());
}

function test_compare(): void {
    const a = 24400569094091093912039019089543850580328542852805043n
    const b = 34034240244909504590902901119302940942904944029040950n

    assert 44493059209094029409209402940924902n < 140044940590459049067274048929058908989042385n
    assert 44493059209094029409209402940924902n < a
    assert a < 34034240244909504590902901119302940942904944029040950n
    assert a < b

    assert 44493059209094029409209402940924902n <= 140044940590459049067274048929058908989042385n
    assert 44493059209094029409209402940924902n <= a
    assert a <= 34034240244909504590902901119302940942904944029040950n
    assert a <= b

    assert 44493059209094029409209402940924902n <= 44493059209094029409209402940924902n
    assert 24400569094091093912039019089543850580328542852805043n <= a
    assert a <= 24400569094091093912039019089543850580328542852805043n
    assert a <= a

    assert 40044940590459049067274048929058908989042385n > 44493059209094029409209402940924902n
    assert 34034240244909504590902901119302940942904944029040950n > a
    assert a > 140044940590459049067274048929058908989042385n
    assert b > a

    assert 40044940590459049067274048929058908989042385n >= 44493059209094029409209402940924902n
    assert 34034240244909504590902901119302940942904944029040950n >= a
    assert a >= 140044940590459049067274048929058908989042385n
    assert b >= a

    assert 44493059209094029409209402940924902n <= 44493059209094029409209402940924902n
    assert 24400569094091093912039019089543850580328542852805043n <= a
    assert a <= 24400569094091093912039019089543850580328542852805043n
    assert a <= a
}

function test_literals() : void {
    let num0 = 0n
    assert (num0.toString() == "0")

    let num1 = 127n
    assert (num1.toString() == "127")

    let num2 = 32767n
    assert (num2.toString() == "32767")

    let num3 = 2147483647n
    assert (num3.toString() == "2147483647")

    let num4 = 9223372036854775807n
    assert (num4.toString() == "9223372036854775807")

    let num5 = 170141183460469231731687303715884105727n
    assert (num5.toString() == "170141183460469231731687303715884105727")

    let num6 = 57896044618658097711785492504343953926634992332820282019728792003956564819967n
    assert (num6.toString() == "57896044618658097711785492504343953926634992332820282019728792003956564819967")

    let num1_n = -128n
    assert (num1_n.toString() == "-128")

    let num2_n = -32768n
    assert (num2_n.toString() == "-32768")

    let num3_n = -2147483648n
    assert (num3_n.toString() == "-2147483648")

    let num4_n = -9223372036854775808n
    assert (num4_n.toString() == "-9223372036854775808")

    let num5_n = -170141183460469231731687303715884105728n
    assert (num5_n.toString() == "-170141183460469231731687303715884105728")

    let num6_n = -57896044618658097711785492504343953926634992332820282019728792003956564819968n
    assert (num6_n.toString() == "-57896044618658097711785492504343953926634992332820282019728792003956564819968")

    let num1_sep = 1_991_653_125_841_217_555_434419_9091_123000000_3_3313_5775_3282_29n
    assert (num1_sep.toString() == "19916531258412175554344199091123000000333135775328229")

    let num2_sep = -422_12_3333_9844_3333_3443_34111_43434_1111_11_1_3_3_411909_990081n
    assert (num2_sep.toString() == "-4221233339844333334433411143434111111133411909990081")

    let num0_t: bigint = 0n
    assert (num0_t.toString() == "0")

    let num1_t: bigint = 57896044618658097711785492504343953926634992332820282019728792003956564819967n
    assert (num1_t.toString() == "57896044618658097711785492504343953926634992332820282019728792003956564819967")

    let num2_t: bigint = -9223372036854775808n
    assert (num2_t.toString() == "-9223372036854775808")

    let num3_t: bigint = 1_991_653_125_841_217_555_434419_9091_123000000_3_3313_5775_3282_29n
    assert (num3_t.toString() == "19916531258412175554344199091123000000333135775328229")

    let num4_t: bigint = -422_12_3333_9844_3333_3443_34111_43434_1111_11_1_3_3_411909_990081n
    assert (num4_t.toString() == "-4221233339844333334433411143434111111133411909990081")

    const num0_c = 0n
    assert (num0_c.toString() == "0")

    const num1_c = 1267650600228229401496703205376n
    assert (num1_c.toString() == "1267650600228229401496703205376")

    const num2_c = -1427247692705959881058285969449495136382746624n
    assert (num2_c.toString() == "-1427247692705959881058285969449495136382746624")

    const num3_c = 4_000_000_000_000_000_000_000_100n
    assert (num3_c.toString() == "4000000000000000000000100")

    const num4_c: bigint = -7777777_666666_55555_4444_333_22_1n
    assert (num4_c.toString() == "-7777777666666555554444333221")
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
    assert n0 == 0n
    assert(n0.toString() == "0")

    let n1 = new BigInt(654093)
    assert(n1.toString() == "654093")
    assert n1 == 654093n

    let n2 = new BigInt(b)
    assert(n2.toString() == "44")
    assert n2 == 44n

    let n3 = new BigInt(s)
    assert(n3.toString() == "-17600")
    assert n3 == -17600n

    let n4 = new BigInt(i)
    assert(n4.toString() == "1150483640")
    assert n4 == 1150483640n

    let n5 = new BigInt(l)
    assert(n5.toString() == "-8223372036854775808")
    assert n5 == -8223372036854775808n

    let dec = new BigInt("-12392320390239294724747283477947923471101032")
    assert dec == -12392320390239294724747283477947923471101032n

    const n7 = 12392320390239294724747283477947923471101032n

    /* Testing asIntN() static method */
    // assert BigInt.asIntN(0, n7) == 0n
    // assert BigInt.asIntN(8, n7) == 104n
    // assert BigInt.asIntN(16, n7) == 27752n
    // assert BigInt.asIntN(32, n7) == -737317784n
    // assert BigInt.asIntN(64, n7) == -7098331616643290008n

    /* Testing asUintN() static method */
    // assert BigInt.asUintN(0, n7) == 0n
    // assert BigInt.asUintN(8, n7) == 104n
    // assert BigInt.asUintN(16, n7) == 27752n
    // assert BigInt.asUintN(32, n7) == 3557649512n
    // assert BigInt.asUintN(64, n7) == 11348412457066261608n
}

function test_unary(): void {
    let n = -128n
    assert (n.toString() == "-128")

    let a = 123n;
    assert(a == 123n);
    assert(a.toString() == "123");

    a = -123n;
    assert(a == -123n);
    assert(a.toString() == "-123");

    a = 123n
    assert(a == 123n);
    assert(a.toString() == "123");

    a = -a;
    assert(a == -123n);
    assert(a.toString() == "-123");

    a = -a;
    assert(a == 123n);
    assert(a.toString() == "123");

    let e: bigint;
    assert(a == 123n);
    assert(a.toString() == "123");
    e = -a;

    // Check that original value does not change
    assert(a == 123n);
    assert(a.toString() == "123");
    assert(e == -123n);
    assert(e.toString() == "-123");
    e = a;
    assert(e == 123n);
    assert(e.toString() == "123");

    let b = -123n;
    assert(b == -123n)
    assert(b.toString() == "-123");

    let c = -(123n);
    assert(c == -123n)
    assert(c.toString() == "-123");

    // Double unary minus
    let d = -(-123n);
    assert(d == 123n);
    assert(d.toString() == "123");

    // Triple unary minux
    let f = -(-(-123n));
    assert(f == -123n);
    assert(f.toString() == "-123");

    a = new BigInt(321);
    assert(a.toString() == "321")
    assert(a == 321n)

    b = -a;
    assert(a.toString() == "321")
    assert(a == 321n)
    assert(b == -321n);
    assert(b.toString() == "-321");
}

function test_multiplication(): void {
    const a = 23443495146314363289895841n
    const b = 245000234343499329134n
    const c = -245000234343499329134n

    /* Multiplication testing (*) */
    assert 978667632325344545n * 4534000101n == 4437279143808543031889799045n
    assert a * b == 5743661804677708098900659843374372544236731694n
    assert a * c == -5743661804677708098900659843374372544236731694n
    assert a * 0n == 0n
    assert c * 0n == 0n

    
    /* Division testing (/) */
    assert 39735235034886462n / 89221422n == 445355321n
    assert a / b == 95687n
    assert a / c == -95687n
    assert 0n / a == 0n

    let err = false;
    try {
        a / 0n
    } catch (e) {
        if (e instanceof Error) {
            err = true
        }
    }
    assert err

    /* Remainder of the division (%) */
    assert 493433405047004109n % 111114444n == 18100749n
    assert a % b == a % c
    assert 0n % a == 0n

    err = false;
    try {
        a % 0n
    } catch (e) {
        if (e instanceof Error) {
            err = true
        }
    }
    assert err
}

function test_addition_1(): void {
    const a = 97567789101304567800013210071n
    const b = -533923234343411557221n
    const c = 0n;

    /* Minus testing (-) */
    assert (-a == -97567789101304567800013210071n)
    assert (-b == 533923234343411557221n)
    assert (-c == -0n)
    assert (-(-a) == a)
    assert (-(-b) == b)
    assert (-(-c) == c)

    /* Plus testing (+) */
    assert +a == a
    assert +b == b
    assert +c == 0n
}

function test_addition_2(): void {
    const a = 18446744073709551616n;
    const b = 36893488147419103232n;
    const c = -10000000000000000000n;
    
    /* Addition testing (+) */
    assert 999999999999999n + 1n == 1000000000000000n
    assert a + b == 55340232221128654848n
    assert a + a == b
    assert a + c == 8446744073709551616n
    assert a + b + b == 92233720368547758080n
}

function test_subtraction(): void {
    const a = 18446744073709551616n;
    const b = 36893488147419103232n;
    const c = -10000000000000000000n;

    // /* Subtraction testing (-) */
    assert 999999999999999n - 1n == 999999999999998n
    assert b - a == a
    assert a - b == -18446744073709551616n
    assert b - a - a == 0n
}

function test_inc_dec(): void {
    const a = 340282366920938463463374607431768211456n
    const b = -2313455919991034304490n
    
    /* Increment testing */
    /* Decrement testing */
}

function test_shift(): void {
    const a = 245599210405555256299145n
    
    /* Testing left shift (<<) */
    assert a << 100n == 311333986486181324779687697000809288883015536628203520n
    assert a << 0n == a

    /* Testing right shift (>>) */
    assert a >> 60n == 213023n
    assert a >> 0n == a
}

function test_bitwise(): void {
    const a = 123456789123456789123456789123456789123456789123456789n
    let b = 123456790n
    const zero = 0n

    /* Testing bitwise NOT (~) */
    assert ~zero == -1n
    assert ~a == -123456789123456789123456789123456789123456789123456790n
    
    /* Testing bitwise AND (&) */
    /* Testing bitwise XOR (^) */
    /* Testing bitwise OR (|) */
}

function main() : void {
    test_create_empty_bigint();
    test_bigint_as_string();
    test_invalid_bigint();
    test_multiply();
    test_plus();
    test_minus();
    test_unary_minus();
    test_divide();
    test_module();
    test_bitwise_and();
    test_bitwise_or();
    test_bitwise_xor();
    test_left_shift();
    test_right_shift();
    test_type();
    test_assignment();
    test_compare();
    test_literals();
    test_cast();
    test_bigint_methods();
    test_unary();
    test_multiplication();
    test_addition_1();
    test_addition_2();
    test_subtraction();
    test_inc_dec();
    test_shift();
    test_bitwise();
}
