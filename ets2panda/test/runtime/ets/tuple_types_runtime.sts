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

type num_str_str = [number, string, string];
type num_str_str_with_spread = [num_str_str, ...number[]];

class A {
    foo(): int {
        return 1;
    }
}

class B extends A {
    override foo(): int  {
        return 2;
    }
}

class TupleProvider<X> {
    memb: [X, X];
    constructor(value: [X, X]) { this.memb = value;}
    public publish(): [X, X] { return this.memb; }
}


function main(): void {
    const tup_1: [string, number] = ["a", 12];

    assert(tup_1[0] == "a");
    assert(tup_1[1] == 12);

    const tup_2: num_str_str[] = [
        [13, "A", "D"],
        [14, "B", "E"],
        [25, "C", "F"],
    ];

    const tup_3: num_str_str_with_spread[] = [
        [tup_2[0], 250],
        [tup_2[1], 250, 260],
        [tup_2[0], 300, 300, 300],
    ];

    const sum = tup_3[0][1] + tup_3[1][1] + tup_3[1][2] + tup_3[2][1] + tup_3[2][2] + tup_3[2][3];
    assert(sum == 1660);

    // Runs correctly, but fails on verifier
    // It sees the type of `tup_3[0][0]` as an `Object`, what it really is an Array type.

    // tup_3[0][0][0]++;
    // assert(tup_3[0][0][0] == 14);
    // tup_3[0][0][0] = 4;
    // assert(tup_3[0][0][0] == 4);

    let int_update: [int] = [42];
    assert(int_update[0] == 42);
    assert(int_update[0]++ == 42);
    assert(int_update[0] == 43);
    assert(++int_update[0] == 44);
    int_update[0]++;
    assert(int_update[0] == 45);

    let spread_tup: [Number, ...Number[]] = [6 as double,7 as double,8 as double, 9 as double, 10 as double];
    let num_arr: Number[] = [1 as double,2 as double,3 as double,4 as double,5 as double,  6 as double];

    spread_tup = num_arr;

    let test_arr: Number[] = [1 as double,2 as double,3 as double,4 as double,5 as double, 6 as double];
    for(let idx = 0; idx < spread_tup.length; idx++){
        assert(spread_tup[idx] == test_arr[idx]);
    }

    let tup_4: [number, number] = [11,2];
    let prim_num_arr: number[] = [3,4];

    prim_num_arr = tup_4;

    let test_arr_2: number[] = [11, 2];
    assert(prim_num_arr[0] == test_arr_2[0]);
    assert(prim_num_arr[1] == test_arr_2[1]);


    let tup_8: [number, string][];
    tup_8 = [[1, "E"], [2, "F"], [3, "G"]];
    assert(tup_8[0][0] == 1 && tup_8[0][1] == "E");
    assert(tup_8[1][0] == 2 && tup_8[1][1] == "F");
    assert(tup_8[2][0] == 3 && tup_8[2][1] == "G");

    // #15570 - test ArrayExpr assignability with individual element types
    // let tup_10: [number, int, string, boolean, Object] = [1, 2, "I", false, new Object()];
    // let var_float: float = tup_10[1];
    // let var_float_2: float = 2.0;
    // assert(var_float == var_float_2);
    // let tup_11: [int, number, string, boolean, Object] = [6, 7, "J", true, 789];
    // NOTE: Bug in op_assignment lowering (removes const from property)
    // tup_11[0] += new Short(2 as short);
    // assert(tup_11[0] == 8);
    // assert(tup_11[4] == (789 as Object));

    let tup_12: [number, ...number[]] = [1, 2, 3, 4];
    try {
        tup_12[4];
    } catch (e: ArrayIndexOutOfBoundsError) {
    } catch (f) {
        assert(false);
    }

    let tup_13: [number, number] = [8, 9];
    let tup_14: [number, number] = [10, 11];

    tup_13 = tup_14;
    assert(tup_13[0] == 10);
    assert(tup_13[1] == 11);
    tup_13[0] = 12;
    tup_13[1] = Double.valueOf(13.0);
    assert(tup_13[0] == 12);
    assert(tup_13[1] == 13);

    let a_b_tup: [A, A, B] = [new A(), new B(), new B()];
    assert(a_b_tup[0].foo() == 1);
    assert(a_b_tup[1].foo() == 2);
    assert(a_b_tup[2].foo() == 2);

    let number_tup: [Double, Double] = [42.0, 43.0];
    let tn: TupleProvider<number> = new TupleProvider<number>(number_tup);
    let result: [Number, Number] = tn.publish();
    assert result[0] == 42.0;
}
