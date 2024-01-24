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
    assert (542.910991 & -1903.2040221) == 16
    assert (-542.910991 & 1903.2040221) == 1378
    assert (-542.910991 & -1903.2040221) == -1920
    assert (9E120 & 56.75) == 56
    assert (0.0 & 0.0) == 0
    assert (NaN & 42.131330352) == 0
    assert (-NaN & -23432.34110144432) == 0
    assert (Infinity & -94.24445985981884) == 9223372036854775714
    assert (-Infinity & 94.24445985981884) == 0

    // Testing "or" operator: 
    assert (542.910991 | 1903.2040221) == 1919
    assert (542.910991 | -1903.2040221) == -1377
    assert (-542.910991 | 1903.2040221) == -17
    assert (-542.910991 | -1903.2040221) == -525
    assert (9E120 | 0) == 9223372036854775807
    assert (824E3 | 21.018763) == 824021
    assert (1.0 | 0.1) == 1
    assert (NaN | 0.2) == 0
    assert (-NaN | 0.3) == 0
    assert (Infinity | 0.4) == 9223372036854775807
    assert (-Infinity | 0.5) == -9223372036854775808

    // Testing "xor" operator: 
    assert (542.910991 ^ 1903.2040221) == 1393
    assert (542.910991 ^ -1903.2040221) == -1393
    assert (-542.910991 ^ 1903.2040221) == -1395
    assert (-542.910991 ^ -1903.2040221) == 1395
    assert (49509.2348100001 ^ 49509.2348100001) == 0
    assert (9E120 ^ 1.2) == 9223372036854775806
    assert (824E3 ^ 21.018763) == 824021
    assert (NaN ^ 99854258.24) == 99854258
    assert (-NaN ^ 30483040.293244) == 30483040
    assert (Infinity ^ 1.2) == 9223372036854775806
    assert (-Infinity ^ 10049329.80001) == -9223372036844726479

    // Testing "left shift" operator:
    assert (1E-100 << 0.0) == 0
    assert (0.00003 << 12.13) == 0
    assert (42.109 << 0.0120939) == 42
    assert (1.409240940 << 17.3) == 131072
    assert (4342435.309421 << 3.1) == 34739480
    assert (9010034745.3449093132 << 7.000000000001) == 1153284447360
    assert (-423.14981 << 20.32) == -443547648
    assert (500.13 << 128.3440) == 500
    assert (500.45 << 121.10000002) == -1729382256910270464
    assert (NaN << 330.3911) == 0
    assert (-NaN << 12.91213) == 0
    assert (Infinity << 1.0092) == -2
    assert (-Infinity << 1.0092) == 0
    assert (-52242.2301 << -8.7) == -1297036692682702848
    assert (52242.2301 << -8.7) == 1297036692682702848

    // Testing "right shift" operator:
    assert (1E-100 >> 0.0) == 0
    assert (0.00003 >> 12.13) == 0
    assert (42.109 >> 0.0120939) == 42
    assert (1.409240940 >> 17.3) == 0
    assert (4342435.309421 >> 3.1) == 542804
    assert (9010034.3449093132 >> 3.000000000001) == 1126254
    assert (-4599090490.24 >> 11) == -2245650
    assert (500.13 >> 128.3440) == 500
    assert (500.45 >> 121.10000002) == 0
    assert (NaN >> 11.000003) == 0
    assert (-NaN >> 7.912130001) == 0
    assert (Infinity >> 61) == 3
    assert (-Infinity >> 61) == -4
    assert (132090941883.34343 >> -32.2) == 30
    assert (-132090941883.34343 >> -32.2) == -31

    // Testing "unsigned right shift" operator:
    assert (1E-100 >>> 0.0) == 0
    assert (0.00003 >>> 12.13) == 0
    assert (42.109 >>> 0.0120939) == 42
    assert (1.409240940 >>> 17.3) == 0
    assert (4342435.309421 >>> 3.1) == 542804
    assert (9010034.3449093132 >>> 3.000000000001) == 1126254
    assert (-4599090490.24 >>> 11) == 9007199252495342
    assert (500.13 >>> 128.3440) == 500
    assert (500.45 >>> 121.10000002) == 0
    assert (NaN >>> 11.000003) == 0
    assert (-NaN >>> 7.912130001) == 0
    assert (Infinity >>> 61.8) == 3
    assert (-Infinity >>> 61.8) == 4
    assert (132090941883.34343 >>> -32.2) == 30
    assert (-132090941883.34343 >>> -32.2) == 4294967265

    // Testing "bitwise complement" operator
    assert ~0 == -1
    assert ~0.000034 == -1
    assert ~39530.93 == -39531
    assert ~93718001.5424230894 == -93718002
    assert ~Infinity == -9223372036854775808
    assert ~-Infinity == 9223372036854775807
    assert ~NaN == -1   
    assert ~-NaN == -1
    assert ~1E210 == -9223372036854775808
    assert ~-1E210 ==  9223372036854775807
    assert ~56E5 == -5600001
    assert ~-56E5 == 5599999

    /* ---- Run time tests ---- */

    // Testing "and" operator:
    assert And(542.910991, -1903.2040221) == 16
    assert And(-542.910991, 1903.2040221) == 1378
    assert And(-542.910991, -1903.2040221) == -1920
    assert And(9E120, 56.75) == 56
    assert And(0.0, 0.0) == 0
    assert And(NaN, 42.131330352) == 0
    assert And(-NaN, -23432.34110144432) == 0
    assert And(Infinity, -94.24445985981884) == 9223372036854775714
    assert And(-Infinity, 94.24445985981884) == 0

    // Testing "or" operator: 
    assert Or(542.910991, 1903.2040221) == 1919
    assert Or(542.910991, -1903.2040221) == -1377
    assert Or(-542.910991, 1903.2040221) == -17
    assert Or(-542.910991, -1903.2040221) == -525
    assert Or(9E120, 0) == 9223372036854775807
    assert Or(824E3, 21.018763) == 824021
    assert Or(1.0, 0.1) == 1
    assert Or(NaN, 0.2) == 0
    assert Or(-NaN, 0.3) == 0
    assert Or(Infinity, 0.4) == 9223372036854775807
    assert Or(-Infinity, 0.5) == -9223372036854775808

    // Testing "xor" operator: 
    assert Xor(542.910991, 1903.2040221) == 1393
    assert Xor(542.910991, -1903.2040221) == -1393
    assert Xor(-542.910991, 1903.2040221) == -1395
    assert Xor(-542.910991, -1903.2040221) == 1395
    assert Xor(49509.2348100001, 49509.2348100001) == 0
    assert Xor(9E120, 1.2) == 9223372036854775806
    assert Xor(824E3, 21.018763) == 824021
    assert Xor(NaN, 99854258.24) == 99854258
    assert Xor(-NaN, 30483040.293244) == 30483040
    assert Xor(Infinity, 1.2) == 9223372036854775806
    assert Xor(-Infinity, 10049329.80001) == -9223372036844726479

    // Testing "left shift" operator:
    assert LeftShift(1E-100, 0.0) == 0
    assert LeftShift(0.00003, 12.13) == 0
    assert LeftShift(42.109, 0.0120939) == 42
    assert LeftShift(1.409240940, 17.3) == 131072
    assert LeftShift(4342435.309421, 3.1) == 34739480
    assert LeftShift(9010034745.3449093132, 7.000000000001) == 1153284447360
    assert LeftShift(-423.14981, 20.32) == -443547648
    assert LeftShift(500.13, 128.3440) == 500
    assert LeftShift(500.45, 121.10000002) == -1729382256910270464
    assert LeftShift(NaN, 330.3911) == 0
    assert LeftShift(-NaN, 12.91213) == 0
    assert LeftShift(Infinity, 1.0092) == -2
    assert LeftShift(-Infinity, 1.0092) == 0
    assert LeftShift(-52242.2301, -8.7) == -1297036692682702848
    assert LeftShift(52242.2301,-8.7) == 1297036692682702848

    // Testing "right shift" operator:
    assert RightShift(1E-100, 0.0) == 0
    assert RightShift(0.00003, 12.13) == 0
    assert RightShift(42.109, 0.0120939) == 42
    assert RightShift(1.409240940, 17.3) == 0
    assert RightShift(4342435.309421, 3.1) == 542804
    assert RightShift(9010034.3449093132, 3.000000000001) == 1126254
    assert RightShift(-4599090490.24, 11) == -2245650
    assert RightShift(500.13, 128.3440) == 500
    assert RightShift(500.45, 121.10000002) == 0
    assert RightShift(NaN, 11.000003) == 0
    assert RightShift(-NaN, 7.912130001) == 0
    assert RightShift(Infinity, 61) == 3
    assert RightShift(-Infinity, 61) == -4
    assert RightShift(132090941883.34343, -32.2) == 30
    assert RightShift(-132090941883.34343, -32.2) == -31

    // Testing "unsigned right shift" operator:
    assert UnsignedRightShift(1E-100, 0.0) == 0
    assert UnsignedRightShift(0.00003,12.13) == 0
    assert UnsignedRightShift(42.109, 0.0120939) == 42
    assert UnsignedRightShift(1.409240940, 17.3) == 0
    assert UnsignedRightShift(4342435.309421, 3.1) == 542804
    assert UnsignedRightShift(9010034.3449093132, 3.000000000001) == 1126254
    assert UnsignedRightShift(-4599090490.24, 11) == 9007199252495342
    assert UnsignedRightShift(500.13, 128.3440) == 500
    assert UnsignedRightShift(500.45, 121.10000002) == 0
    assert UnsignedRightShift(NaN, 11.000003) == 0
    assert UnsignedRightShift(-NaN, 7.912130001) == 0
    assert UnsignedRightShift(Infinity, 61.8) == 3
    assert UnsignedRightShift(-Infinity, 61.8) == 4
    assert UnsignedRightShift(132090941883.34343, -32.2) == 30
    assert UnsignedRightShift(-132090941883.34343, -32.2) == 4294967265
 
    // Testing "bitwise complement" operator
    assert Inversion(0) == -1
    assert Inversion(0.000034) == -1
    assert Inversion(39530.93) == -39531
    assert Inversion(93718001.5424230894) == -93718002
    assert Inversion(Infinity) == -9223372036854775808
    assert Inversion(-Infinity) == 9223372036854775807
    assert Inversion(NaN) == -1   
    assert Inversion(-NaN) == -1
    assert Inversion(1E210) == -9223372036854775808
    assert Inversion(-1E210) ==  9223372036854775807
    assert Inversion(56E5) == -5600001
    assert Inversion(-56E5) == 5599999
}
