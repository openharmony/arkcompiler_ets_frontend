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

class A { foo() {}}
class B extends A { bar() {}}

type num_str_str_type = [number, string, string];
type num_str_str_with_spread = [num_str_str_type, ...number[]];

function foo(a0: number, args: [...number[]]): number {
    return 2;
}


function main(): void {
    const tup_arr_1: num_str_str_type[] = [
        [0, "a", "d"],
        [1, "b", "e"],
        [2, "c", "f"],
    ];

    const tup_arr_2: num_str_str_with_spread[] = [
        [tup_arr_1[0], 250],
        [tup_arr_1[1], 250, 260],
        [tup_arr_1[0], 300, 300, 300],
    ];

    const a_var = tup_arr_2[0][1] + tup_arr_2[1][1] + tup_arr_2[2][1];
    const b_var = tup_arr_2[1][2] + tup_arr_2[2][2];
    const c_var = tup_arr_2[2][2];

    foo(tup_arr_1[0][0], [tup_arr_2[0][1]]);
    foo(tup_arr_1[1][0], [tup_arr_2[1][1], tup_arr_2[1][2]]);

    let arr: Object[] = [1,2,3,4,5];
    let double_ref_tup: [Number, Number, Number] = [6 as double, 7 as double, 8 as double];
    let a_arr: A[];
    let b_tup: [B, B] = [new B(), new B()];
    let b_arr: B[] = [new B(), new B()];

    arr = double_ref_tup;
    a_arr = b_tup;
    b_arr = b_tup;

    let spread_tup: [Number, ...Number[]] = [6 as double,7 as double,8 as double, 9 as double, 10 as double];
    let num_ref_arr: Number[] = [1 as double,2 as double,3 as double,4 as double,5 as double];

    spread_tup = num_ref_arr;

    let num_tup: [number, number] = [11,2];
    let num_prim_arr: number[] = [3,4];

    num_prim_arr = num_tup;

    let d_var: [number, string] = [1, "A"];
    let e_var: [number, string, boolean] = [1, "A", true];
    let f_var: [number, string, boolean, number, string];
    f_var = [1, "A", true, 20, "B"];

    let g_var: [number, string][];
    g_var = [[1, "A"], [2, "B"], [3, "C"]];

    // #15570 - test ArrayExpr assignability with individual element types
    // let h_var: [number, int, string, boolean, Object] = [1, 2, "asd", false, new Object()];
    // let i_var: float = h_var[1];
    // let j_var: [int, number, string, boolean, Object] = [6, 7, "abc", true, 666];
    // NOTE: Bug in op_assignment lowering (removes const from property)
    // j_var[0] += new Short(2 as short);

    let empty: [] = [];
}
