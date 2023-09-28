/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

export function Animations() {
    var anyvar: any
    let symvar: symbol
    let unknown_t: unknown
    let undef_t: undefined
    let null_t: null
    let state = 0 
    
    let flag: boolean = false;

    let status = { name:"A", idx:0, handler:"foo" }
        
    type Person = [string, number];
    var user: Person; 
    user = ["John", 32];
    let age = user[1]
    
    type Point = { x: number; y: number };
    type P = keyof Point;
    type AxeX = Point["x"];
    type P_NULL = P | null;
    type P_UNDEF = P | undefined;
    type P_ANY = P | any;
    type P_P = P | Person;
    type P_P_NULL = P | Person | null;    

    let typeU = typeof user;
    
    function isNumber(x: any): x is number {
        return typeof x === "number";
    }

    var regex = /go*d/;

    throw "labuda";
}

const c = "c";
const d = 10;
type ComputedPropertyT = {
    a: string; // String-like name
    5: string; // Number-like name
    [c]: string; // String-like name
    [d]: string; // Number-like name
}

class LiteralAsPropertyName {
    2:string;
    "Two": number;
}

let litAsPropName: LiteralAsPropertyName = { 
   2:"two",
   "Two":2 
} 


type Dictionary = {
    [key: string]: unknown;
}
let dict: Dictionary;

function bar(key: string, val: any) {
    if (key in dict) {
        dict[key] = val;
    }
}

interface I1 {
    m1(): number;
    m2(): void;
}

interface I2 {
    m2(): string;
    m3(): boolean;
}

type IntersectionT = I1 & I2;

type DescribableFunction = { 
    description:string;
    (someArg: number): boolean
}
function callFunctionObject(fn: DescribableFunction) {
    console.log(fn.description + " returned " + fn(5));
}
const funcWithDescr: DescribableFunction = (x: number) => x % 2 == 0;
funcWithDescr.description = "isEven";
callFunctionObject(funcWithDescr);

class G<T> {
    val: T;
    getVal(): T { return this.val; }
}
class H extends G<{x: 2}> {}
let g: G<{y: string}> = new G<{y: "constant"}>();
function generic<T>(t: T): void {}
generic<{z: boolean}>({z: true});

function type_assertions(): void {
    let num = <any>1;
    const myCanvas = <HTMLCanvasElement>document.getElementById("main_canvas");
}

function dynamic_properties(): void {
    let x = { a: 5, b: "text" };
    x["c"] = 100200;
    console.log(x["c"]);
    
    let y: any = { q: 100, w: true };
    y.e = "dynamic";
    console.log(y.e);
}

function generic_array_type(): void {
    let x: Array<string> = ["1", "2", "3"];
    let y: Array<number> = new Array(1, 2, 3);
    let z: number[] = [1, 2, 3];

    function arrayFunc<T extends Object>(array: Array<T>): Array<string> {
        return array.map(x => x.toString());
    }
}