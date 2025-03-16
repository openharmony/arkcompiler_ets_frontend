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

function And(a: double, b: double): long {
    return a & b
}

function Or(a: double, b: double): long {
    return a | b
}

function Xor(a: double, b: double): long {
    return a ^ b
}

function LeftShift(a: double, b: double): long {
    return a << b
}

function RightShift(a: double, b: double): long {
    return a >> b
}

function UnsignedRightShift(a: double, b: double): long {
    return a >>> b
}
 
function Inversion(a: double): long {
    return ~a;
}

function main(): void {
    /* ---- Compile time tests ---- */

    // Testing "and" operator:
    assertEQ((542.910991 & -1903.2040221), 16)
    assertEQ((-542.910991 & 1903.2040221), 1378)
    assertEQ((-542.910991 & -1903.2040221), -1920)
    assertEQ((9E120 & 56.75), 56)
    assertEQ((0.0 & 0.0), 0)
    assertEQ((NaN & 42.131330352), 0)
    assertEQ((-NaN & -23432.34110144432), 0)
    assertEQ((Infinity & -94.24445985981884), 9223372036854775714)
    assertEQ((-Infinity & 94.24445985981884), 0)

    // Testing "or" operator: 
    assertEQ((542.910991 | 1903.2040221), 1919)
    assertEQ((542.910991 | -1903.2040221), -1377)
    assertEQ((-542.910991 | 1903.2040221), -17)
    assertEQ((-542.910991 | -1903.2040221), -525)
    assertEQ((9E120 | 0), 9223372036854775807)
    assertEQ((824E3 | 21.018763), 824021)
    assertEQ((1.0 | 0.1), 1)
    assertEQ((NaN | 0.2), 0)
    assertEQ((-NaN | 0.3), 0)
    assertEQ((Infinity | 0.4), 9223372036854775807)
    assertEQ((-Infinity | 0.5), -9223372036854775808)

    // Testing "xor" operator: 
    assertEQ((542.910991 ^ 1903.2040221), 1393)
    assertEQ((542.910991 ^ -1903.2040221), -1393)
    assertEQ((-542.910991 ^ 1903.2040221), -1395)
    assertEQ((-542.910991 ^ -1903.2040221), 1395)
    assertEQ((49509.2348100001 ^ 49509.2348100001), 0)
    assertEQ((9E120 ^ 1.2), 9223372036854775806)
    assertEQ((824E3 ^ 21.018763), 824021)
    assertEQ((NaN ^ 99854258.24), 99854258)
    assertEQ((-NaN ^ 30483040.293244), 30483040)
    assertEQ((Infinity ^ 1.2), 9223372036854775806)
    assertEQ((-Infinity ^ 10049329.80001), -9223372036844726479)

    // Testing "left shift" operator:
    assertEQ((1E-100 << 0.0), 0)
    assertEQ((0.00003 << 12.13), 0)
    assertEQ((42.109 << 0.0120939), 42)
    assertEQ((1.409240940 << 17.3), 131072)
    assertEQ((4342435.309421 << 3.1), 34739480)
    assertEQ((9010034745.3449093132 << 7.000000000001), 1153284447360)
    assertEQ((-423.14981 << 20.32), -443547648)
    assertEQ((500.13 << 128.3440), 500)
    assertEQ((500.45 << 121.10000002), -1729382256910270464)
    assertEQ((NaN << 330.3911), 0)
    assertEQ((-NaN << 12.91213), 0)
    assertEQ((Infinity << 1.0092), -2)
    assertEQ((-Infinity << 1.0092), 0)
    assertEQ((-52242.2301 << -8.7), -1297036692682702848)
    assertEQ((52242.2301 << -8.7), 1297036692682702848)

    // Testing "right shift" operator:
    assertEQ((1E-100 >> 0.0), 0)
    assertEQ((0.00003 >> 12.13), 0)
    assertEQ((42.109 >> 0.0120939), 42)
    assertEQ((1.409240940 >> 17.3), 0)
    assertEQ((4342435.309421 >> 3.1), 542804)
    assertEQ((9010034.3449093132 >> 3.000000000001), 1126254)
    assertEQ((-4599090490.24 >> 11), -2245650)
    assertEQ((500.13 >> 128.3440), 500)
    assertEQ((500.45 >> 121.10000002), 0)
    assertEQ((NaN >> 11.000003), 0)
    assertEQ((-NaN >> 7.912130001), 0)
    assertEQ((Infinity >> 61), 3)
    assertEQ((-Infinity >> 61), -4)
    assertEQ((132090941883.34343 >> -32.2), 30)
    assertEQ((-132090941883.34343 >> -32.2), -31)

    // Testing "unsigned right shift" operator:
    assertEQ((1E-100 >>> 0.0), 0)
    assertEQ((0.00003 >>> 12.13), 0)
    assertEQ((42.109 >>> 0.0120939), 42)
    assertEQ((1.409240940 >>> 17.3), 0)
    assertEQ((4342435.309421 >>> 3.1), 542804)
    assertEQ((9010034.3449093132 >>> 3.000000000001), 1126254)
    assertEQ((-4599090490.24 >>> 11), 9007199252495342)
    assertEQ((500.13 >>> 128.3440), 500)
    assertEQ((500.45 >>> 121.10000002), 0)
    assertEQ((NaN >>> 11.000003), 0)
    assertEQ((-NaN >>> 7.912130001), 0)
    assertEQ((Infinity >>> 61.8), 3)
    assertEQ((-Infinity >>> 61.8), 4)
    assertEQ((132090941883.34343 >>> -32.2), 30)
    assertEQ((-132090941883.34343 >>> -32.2), 4294967265)

    // Testing "bitwise complement" operator
    assertEQ(~0, -1)
    assertEQ(~0.000034, -1)
    assertEQ(~39530.93, -39531)
    assertEQ(~93718001.5424230894, -93718002)
    assertEQ(~Infinity, -9223372036854775808)
    assertEQ(~-Infinity, 9223372036854775807)
    assertEQ(~NaN, -1   )
    assertEQ(~-NaN, -1)
    assertEQ(~1E210, -9223372036854775808)
    assertEQ(~-1E210,  9223372036854775807)
    assertEQ(~56E5, -5600001)
    assertEQ(~-56E5, 5599999)

    /* ---- Run time tests ---- */

    // Testing "and" operator:
    assertEQ(And(542.910991, -1903.2040221), 16)
    assertEQ(And(-542.910991, 1903.2040221), 1378)
    assertEQ(And(-542.910991, -1903.2040221), -1920)
    assertEQ(And(9E120, 56.75), 56)
    assertEQ(And(0.0, 0.0), 0)
    assertEQ(And(NaN, 42.131330352), 0)
    assertEQ(And(-NaN, -23432.34110144432), 0)
    assertEQ(And(Infinity, -94.24445985981884), 9223372036854775714)
    assertEQ(And(-Infinity, 94.24445985981884), 0)

    // Testing "or" operator: 
    assertEQ(Or(542.910991, 1903.2040221), 1919)
    assertEQ(Or(542.910991, -1903.2040221), -1377)
    assertEQ(Or(-542.910991, 1903.2040221), -17)
    assertEQ(Or(-542.910991, -1903.2040221), -525)
    assertEQ(Or(9E120, 0), 9223372036854775807)
    assertEQ(Or(824E3, 21.018763), 824021)
    assertEQ(Or(1.0, 0.1), 1)
    assertEQ(Or(NaN, 0.2), 0)
    assertEQ(Or(-NaN, 0.3), 0)
    assertEQ(Or(Infinity, 0.4), 9223372036854775807)
    assertEQ(Or(-Infinity, 0.5), -9223372036854775808)

    // Testing "xor" operator: 
    assertEQ(Xor(542.910991, 1903.2040221), 1393)
    assertEQ(Xor(542.910991, -1903.2040221), -1393)
    assertEQ(Xor(-542.910991, 1903.2040221), -1395)
    assertEQ(Xor(-542.910991, -1903.2040221), 1395)
    assertEQ(Xor(49509.2348100001, 49509.2348100001), 0)
    assertEQ(Xor(9E120, 1.2), 9223372036854775806)
    assertEQ(Xor(824E3, 21.018763), 824021)
    assertEQ(Xor(NaN, 99854258.24), 99854258)
    assertEQ(Xor(-NaN, 30483040.293244), 30483040)
    assertEQ(Xor(Infinity, 1.2), 9223372036854775806)
    assertEQ(Xor(-Infinity, 10049329.80001), -9223372036844726479)

    // Testing "left shift" operator:
    assertEQ(LeftShift(1E-100, 0.0), 0)
    assertEQ(LeftShift(0.00003, 12.13), 0)
    assertEQ(LeftShift(42.109, 0.0120939), 42)
    assertEQ(LeftShift(1.409240940, 17.3), 131072)
    assertEQ(LeftShift(4342435.309421, 3.1), 34739480)
    assertEQ(LeftShift(9010034745.3449093132, 7.000000000001), 1153284447360)
    assertEQ(LeftShift(-423.14981, 20.32), -443547648)
    assertEQ(LeftShift(500.13, 128.3440), 500)
    assertEQ(LeftShift(500.45, 121.10000002), -1729382256910270464)
    assertEQ(LeftShift(NaN, 330.3911), 0)
    assertEQ(LeftShift(-NaN, 12.91213), 0)
    assertEQ(LeftShift(Infinity, 1.0092), -2)
    assertEQ(LeftShift(-Infinity, 1.0092), 0)
    assertEQ(LeftShift(-52242.2301, -8.7), -1297036692682702848)
    assertEQ(LeftShift(52242.2301,-8.7), 1297036692682702848)

    // Testing "right shift" operator:
    assertEQ(RightShift(1E-100, 0.0), 0)
    assertEQ(RightShift(0.00003, 12.13), 0)
    assertEQ(RightShift(42.109, 0.0120939), 42)
    assertEQ(RightShift(1.409240940, 17.3), 0)
    assertEQ(RightShift(4342435.309421, 3.1), 542804)
    assertEQ(RightShift(9010034.3449093132, 3.000000000001), 1126254)
    assertEQ(RightShift(-4599090490.24, 11), -2245650)
    assertEQ(RightShift(500.13, 128.3440), 500)
    assertEQ(RightShift(500.45, 121.10000002), 0)
    assertEQ(RightShift(NaN, 11.000003), 0)
    assertEQ(RightShift(-NaN, 7.912130001), 0)
    assertEQ(RightShift(Infinity, 61), 3)
    assertEQ(RightShift(-Infinity, 61), -4)
    assertEQ(RightShift(132090941883.34343, -32.2), 30)
    assertEQ(RightShift(-132090941883.34343, -32.2), -31)

    // Testing "unsigned right shift" operator:
    assertEQ(UnsignedRightShift(1E-100, 0.0), 0)
    assertEQ(UnsignedRightShift(0.00003,12.13), 0)
    assertEQ(UnsignedRightShift(42.109, 0.0120939), 42)
    assertEQ(UnsignedRightShift(1.409240940, 17.3), 0)
    assertEQ(UnsignedRightShift(4342435.309421, 3.1), 542804)
    assertEQ(UnsignedRightShift(9010034.3449093132, 3.000000000001), 1126254)
    assertEQ(UnsignedRightShift(-4599090490.24, 11), 9007199252495342)
    assertEQ(UnsignedRightShift(500.13, 128.3440), 500)
    assertEQ(UnsignedRightShift(500.45, 121.10000002), 0)
    assertEQ(UnsignedRightShift(NaN, 11.000003), 0)
    assertEQ(UnsignedRightShift(-NaN, 7.912130001), 0)
    assertEQ(UnsignedRightShift(Infinity, 61.8), 3)
    assertEQ(UnsignedRightShift(-Infinity, 61.8), 4)
    assertEQ(UnsignedRightShift(132090941883.34343, -32.2), 30)
    assertEQ(UnsignedRightShift(-132090941883.34343, -32.2), 4294967265)
 
    // Testing "bitwise complement" operator
    assertEQ(Inversion(0), -1)
    assertEQ(Inversion(0.000034), -1)
    assertEQ(Inversion(39530.93), -39531)
    assertEQ(Inversion(93718001.5424230894), -93718002)
    assertEQ(Inversion(Infinity), -9223372036854775808)
    assertEQ(Inversion(-Infinity), 9223372036854775807)
    assertEQ(Inversion(NaN), -1   )
    assertEQ(Inversion(-NaN), -1)
    assertEQ(Inversion(1E210), -9223372036854775808)
    assertEQ(Inversion(-1E210),  9223372036854775807)
    assertEQ(Inversion(56E5), -5600001)
    assertEQ(Inversion(-56E5), 5599999)
}
