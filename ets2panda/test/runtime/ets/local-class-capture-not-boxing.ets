/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

class UserClassType
{
    v : int = 0;
    constructor (p : int)
    {
        this.v = p;
    }

    override toString() : string {
        return Int.valueOf(this.v).toString();
    }
}

enum UserEnumType 
{ 
    Red, 
    Green, 
    Blue
};

let g_array : int [] = [1,2,3];
let g_array2 : int [] = [11,12,13];
let g_Array : Array<Int> = new Array<Int>(new Int(4), new Int(5), new Int(6));
let g_Array2 : Array<Int> = new Array<Int>(new Int(14), new Int(15), new Int(16));
let g_Object : Object = new Object();
let g_Object2 : Object = new Object();
let g_Class : UserClassType = new UserClassType(25);
let g_Class2 : UserClassType = new UserClassType(250);



class GlobalClass
{
    static s_field : int = 13;
    field : int = 14;

    static s_method_not_boxing_local_class() {
        // predefined value types
        let l_number : number = 1;
        let l_byte : byte = 2;
        let l_short : short = 3;
        let l_int : int = 4;
        let l_long : long = 5;
        let l_float : float = 6.0;
        let l_double : double = 7.0;
        let l_boolean : boolean = false;
        let l_char : char = c'x';
        
        // user defined value types
        let l_enum : UserEnumType = UserEnumType.Red;

        // predefined reference types
        let l_Number : Number = new Number(11);
        let l_Byte : Byte = new Byte(12 as byte);
        let l_Short : Short = new Short(13 as short);
        let l_Int : Int = new Int(14 as int);
        let l_Long : Long = new Long(15 as long);
        let l_Float : Float = new Float(16.0);
        let l_Double : Double = new Double(17.0);
        let l_Boolean: Boolean = new Boolean(false);
        let l_Char : Char = new Char(c'X');

        let l_string : string = "something";
        let l_String : String = new String("Something");
        let l_array : int [] = g_array;
        let l_Array : Array<Int> = g_Array;
        //let l_bigint : bigint = 20n;
        //let l_BigInt : BigInt = new BigInt(21n);
        let l_Object : Object = g_Object;

        // user defined reference types
        let l_Class : UserClassType = g_Class;

        class LocalClassNotBoxing
        {
            local_field : int = 100;
            static local_s_field : int = 200;

            static local_s_method(lp : int) : void 
            {
                assertEQ(lp, 30)
                assertEQ(LocalClassNotBoxing.local_s_field, 200)
            } 

            local_method(lp : int) : void 
            {
                // Parameter
                assertEQ(lp, 40)
                // Local class object field
                assertEQ(this.local_field, 100)
                // Local class static field
                assertEQ(LocalClassNotBoxing.local_s_field, 200)
                // Predefined value types
                assertEQ(l_number, 1)
                assertEQ(l_byte, 2)
                assertEQ(l_short, 3)
                assertEQ(l_int, 4)
                assertEQ(l_long, 5)
                assertEQ(l_float, 6)
                assertEQ(l_double, 7)
                assertEQ(l_boolean, false)
                assertEQ(l_char, c'x')
                // User defined value type
                assertEQ(l_enum, UserEnumType.Red)
                // Predefined reference types
                assertEQ(l_Number, Number.valueOf(11))
                assertEQ(l_Byte, Byte.valueOf(12 as byte))
                assertEQ(l_Short, Short.valueOf(13 as short))
                assertEQ(l_Int, Int.valueOf(14 as int))
                assertEQ(l_Long, Long.valueOf(15 as long))
                assertEQ(l_Float, Float.valueOf(16 as float))
                assertEQ(l_Double, Double.valueOf(17 as double))
                assertEQ(l_Boolean, Boolean.valueOf(false))
                assertEQ(l_Char, Char.valueOf(c'X'))
                assertEQ(l_string, "something")
                assertEQ(l_String, "Something")
                assertEQ(l_array, g_array)
                assertEQ(l_Array, g_Array)
                assertEQ(l_Object, g_Object)
                assertEQ(l_Class, g_Class)
            }
        };

        LocalClassNotBoxing.local_s_method(30);

        let lc = new LocalClassNotBoxing();
        lc.local_method(40);
    }
}


function main() : int
{
    GlobalClass.s_method_not_boxing_local_class();
    return 0;
}
