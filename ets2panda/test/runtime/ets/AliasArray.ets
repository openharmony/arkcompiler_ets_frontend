/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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


class C<T> {
    constructor (p: T) { this.v = p; }
    v : T;
}

type Alias1Array<T> = T[];
type Alias2Array<T> = C<T>[];
type Alias3Array<T> = C<T>[][];
type Alias4Array<T> = ((p: T) => double)[];
type Alias5Array<T> = (p: T[]) => double;
type Alias6Array<T> = (p: T[], q: T) => double;
type Alias7Array<T1, T2> = (p: T1[], q: T2) => double;
type Alias8Array<T> = [T][];
type Alias9Array<T> = [C<T>][];

function main() 
{
    let v1 : double[] = [1,2,3];                       // double[]
    v1[0] = new Int(4);
    assertEQ(v1[0], 4)
    assertEQ(v1[1], 2)
    assertEQ(v1[2], 3)
    
    let v2 : Alias1Array<double> =  [5, 6, 7];         // double[]
    v2[0] = new Int(8);
    assertEQ(v2[0], 8)
    assertEQ(v2[1], 6)
    assertEQ(v2[2], 7)

    let v3 : Alias2Array<double> = [new C<double>(9)];  // C<Double>[]
    assertEQ(v3[0].v, 9)
    v3[0].v = 10;
    assertEQ(v3[0].v, 10)

    let v4 : Alias3Array<double> = [[new C<double>(11)]];  // C<Double>[][]
    assertEQ(v4[0][0].v, 11)
    v4[0][0].v = 12;
    assertEQ(v4[0][0].v, 12)

    let v5 : Alias4Array<double> = [(p : double) : double => { return p; }];  // [(p: Double)=>Double]
    assertEQ(v5[0](13), 13)

    let v6 : Alias5Array<double> = (p : double[]) : double => { return p[0]; };  // (p: double[])=>Double
    assertEQ(v6([14.0]), 14)

    // let v7 : Alias6Array<double> = (p : double[], q: double) : double => { return p[0]; };  // (p: Double[], q: Double)=>Double
    // assertEQ(v7([15.0], 16), 15)

    let v9 : Alias7Array<double, double> = (p : double[], q: double) : double => { return p[0]; };  // (p: double[], q: Double)=>Double
    assertEQ(v9([17.0], 18), 17)

    let v10 : Alias8Array<double> = [[new Int(18)]];  //  [double][]
    assertEQ(v10[0][0], 18)

    let v11 : Alias9Array<double> = [[new C<double>(19)]]; // [C<Double>][]
    assertEQ(v11[0][0].v, 19)
}
