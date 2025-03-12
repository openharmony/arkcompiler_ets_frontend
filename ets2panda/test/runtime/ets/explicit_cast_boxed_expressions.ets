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

let testByte: Byte = new Byte(42 as byte);
let testShort: Short = new Short(42 as short);
let testInt: Int = new Int(42 as int);
let testLong: Long = new Long(42 as long);
let testFloat: Float = new Float(42 as float);
let testDouble: Double = new Double(42 as double);
let testChar: Char = new Char(42 as char);
let testLongValue: Long = 9223372036854775807;

function byte_test(): boolean {
    let Byte_: Byte = new Byte(42 as byte); // ?

    let byte_short  = Byte_ as Short; // ?
    let byte_int    = Byte_ as Int; // ?
    let byte_long   = Byte_ as Long; // ok
    let byte_float  = Byte_ as Float; // ok
    let byte_double = Byte_ as Double; // ok
    let byte_char   = Byte_ as Char; // ok

    // true test Type speciefic operations
    {
        if (byte_double != testDouble || byte_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (byte_char != testChar || byte_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (byte_float != testFloat || byte_float.isNaN() != testFloat.isNaN()) {
            return false;
        }
        if (byte_long != testLong || (byte_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }

        // no int test
        // no short test
        // no byte test
    }
    return true;
}
function short_test(): boolean {
    let Short_: Short = new Short(42 as short);


    let short_byte   = Short_ as Byte;
    let short_short  = Short_ as Short;
    let short_char   = Short_ as Char;
    let short_int    = Short_ as Int;
    let short_long   = Short_ as Long;
    let short_float  = Short_ as Float;
    let short_double = Short_ as Double;


    // true test Type speciefic operations
    {
        if (short_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (short_char != testChar || short_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (short_float != testFloat || short_float.isNaN() != testFloat.isNaN()) {
            return false;
        }
        if (short_long != testLong || (short_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function char_test(): boolean {
    let Char_: Char = new Char(42 as char);

    let char_byte   = Char_ as Byte;
    let char_short  = Char_ as Short;
    let char_char   = Char_ as Char;
    let char_int    = Char_ as Int;
    let char_long   = Char_ as Long;
    let char_float  = Char_ as Float;
    let char_double = Char_ as Double;

    // true test Type speciefic operations
    {
        if (char_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (char_char != testChar || char_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (char_float != testFloat || char_float.isNaN() != testFloat.isNaN()) {
            return false;
        }
        if (char_long != testLong || (char_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function int_test(): boolean {
    let Int_: Int = new Int(42 as int);


    let int_byte    = Int_ as Byte;
    let int_short   = Int_ as Short;
    let int_char    = Int_ as Char;
    let int_int     = Int_ as Int;
    let int_long    = Int_ as Long;
    let int_float   = Int_ as Float;
    let int_double  = Int_ as Double;

    // true test Type speciefic operations
    {
        if (int_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (int_char != testChar || int_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (int_float != testFloat || int_float.isNaN() != testFloat.isNaN()) {
            return false;
        }
        if (int_long != testLong || (int_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function long_test(): boolean {
    let Long_: Long = new Long(42 as long);

    let long_byte   = Long_ as Byte;
    let long_short  = Long_ as Short;
    let long_char   = Long_ as Char;
    let long_int    = Long_ as Int;
    let long_long   = Long_ as Long;
    let long_float  = Long_ as Float;
    let long_double = Long_ as Double;

    // true test Type speciefic operations
    {
        if (long_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (long_char != testChar || long_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (long_float != testFloat || long_float.isNaN() != testFloat.isNaN()) {
            return false;
        }
        if (long_long != testLong || (long_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function float_test(): boolean {
    let Float_: Float = new Float(42 as float);

    let float_byte   = Float_ as Byte;
    let float_short  = Float_ as Short;
    let float_char   = Float_ as Char;
    let float_int    = Float_ as Int;
    let float_long   = Float_ as Long;
    let float_float  = Float_ as Float;
    let float_double = Float_ as Double;
    // true test Type speciefic operations
    {
        if (float_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (float_char != testChar || float_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (float_float != testFloat || float_float.isNaN() != testFloat.isNaN()) { // better to find another way of checking
            return false;
        }
        if (float_long != testLong || (float_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function double_test(): boolean {
    let Double_: Double = new Double(42 as double);

    let double_byte   = Double_ as Byte;
    let double_short  = Double_ as Short;
    let double_char   = Double_ as Char;
    let double_int    = Double_ as Int;
    let double_long   = Double_ as Long;
    let double_float  = Double_ as Float;
    let double_double = Double_ as Double;
    // true test Type speciefic operations
    {
        if (double_double.toExponential() != testDouble.toExponential()) {
            return false;
        }
        if (double_char != testChar || double_char.isBinDigit() != testChar.isBinDigit()) {
            return false;
        }
        if (double_float != testFloat || double_float.isNaN() != testFloat.isNaN()) { // better to find another way of checking
            return false;
        }
        if (double_long != testLong || (double_long = testLongValue) != (testLongValue)) {
            return false; // in fact CTE
        }
        // no int test
        // no short test
        // no byte test
    }
    return true;
}

function boolean_test(): boolean {
    let boolean_: boolean = true;
    let Boolean_: Boolean = new Boolean(true);

    let boolean_boolean = Boolean_ as Boolean;
    return true;
}

function main(): int {
    if (byte_test() && short_test() && char_test() && int_test()
        && long_test() && float_test() && double_test() && boolean_test()) {
        return 0;
    }
    return 1;
}
