/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

    static s_method_boxing_local_class() {
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

        class LocalClassBoxing
        {
            local_field : int = 1000;
            static local_s_field : int = 2000;

            static local_s_method(lp : int) : void 
            {
                assert(lp == 300);
                assert(LocalClassBoxing.local_s_field == 2000);

                LocalClassBoxing.local_s_field = 5000;
                assert(LocalClassBoxing.local_s_field == 5000);
            } 

            local_method(lp : int) : void 
            {
                // Parameter
                assert(lp == 400);
                // Local class object field
                assert(this.local_field == 1000);
                // Local class static field
                assert(LocalClassBoxing.local_s_field == 5000);
                // Outer class static field
                assert(GlobalClass.s_field == 13);
                // Predefined value types
                assert(l_number == 1);
                assert(l_byte == 2);
                assert(l_short == 3);
                assert(l_int == 4);
                assert(l_long == 5);
                assert(l_float == 6);
                assert(l_double == 7);
                assert(l_boolean == false);
                assert(l_char == c'x');
                // User defined value type
                assert(l_enum == UserEnumType.Red);
                // Predefined reference types
                assert(l_Number == Number.valueOf(11));
                assert(l_Byte == Byte.valueOf(12 as byte));
                assert(l_Short == Short.valueOf(13 as short));
                assert(l_Int == Int.valueOf(14 as int));
                assert(l_Long == Long.valueOf(15 as long));
                assert(l_Float == Float.valueOf(16 as float));
                assert(l_Double == Double.valueOf(17 as double));
                assert(l_Boolean == Boolean.valueOf(false));
                assert(l_Char == Char.valueOf(c'X'));
                assert(l_string == "something");
                assert(l_String == "Something");
                // assert(l_array == g_array);
                // assert(l_Array == g_Array);
                assert(l_Object == g_Object);
                assert(l_Class == g_Class);

                this.local_field = 1100;
                LocalClassBoxing.local_s_field = 5100;

                l_number = 101;
                l_byte = 102;
                l_short = 103;
                l_int = 104;
                l_long = 105;
                l_float = 106.0;
                l_double = 107.0;
                l_boolean = true;
                l_char = c'y';
                //l_enum = UserEnumType.Green;

                l_Number = new Number(111);
                l_Byte = new Byte(112 as byte);
                l_Short = new Short(113 as short);
                l_Int = new Int(114 as int);
                l_Long = new Long(115 as long);
                l_Float = new Float(116.0);
                l_Double = new Double(117.0);
                l_Boolean = new Boolean(true);
                l_Char = new Char(c'Y');

                l_string = "something new";
                l_String = new String("Something new");
                l_array = g_array2;
                l_Array = g_Array2;
                l_Object = g_Object2;
                l_Class = g_Class2;
            }
        };
        LocalClassBoxing.local_s_field = 2000;  // due to the jit loop
        LocalClassBoxing.local_s_method(300);

        let lcb = new LocalClassBoxing();
        lcb.local_method(400);        

        assert(lcb.local_field == 1100);
        assert(LocalClassBoxing.local_s_field == 5100);
        assert(l_number == 101);
        assert(l_byte == 102);
        assert(l_short == 103);
        assert(l_int == 104);
        assert(l_long == 105);
        assert(l_float == 106);
        assert(l_double == 107);
        assert(l_boolean == true);
        assert(l_char == c'y');
        
        //assert(l_enum == UserEnumType.Green);
        
        // Predefined reference types
        assert(l_Number == Number.valueOf(111));
        assert(l_Byte == Byte.valueOf(112 as byte));
        assert(l_Short == Short.valueOf(113 as short));
        assert(l_Int == Int.valueOf(114 as int));
        assert(l_Long == Long.valueOf(115 as long));
        assert(l_Float == Float.valueOf(116 as float));
        assert(l_Double == Double.valueOf(117 as double));
        assert(l_Boolean == Boolean.valueOf(true));
        assert(l_Char == Char.valueOf(c'Y'));
        assert(l_string == "something new");
        assert(l_String == "Something new");
        //assert(l_array == g_array2);
        //assert(l_Array == g_Array2);
        assert(l_Object == g_Object2);
        assert(l_Class == g_Class2);
    }
}


function main() : int
{
    GlobalClass.s_method_boxing_local_class();
    return 0;
}
