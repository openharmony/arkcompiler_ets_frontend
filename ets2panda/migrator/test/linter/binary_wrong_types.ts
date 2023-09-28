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

function gets() : string {
  return "ss";
}

let b0 = true;

let c0 = b0 && true;
let c1 = true  && "3";
let c2 = gets() && false;
let c3 = 5 && 6;

let d0 = false || b0;
let d1 = (~"3" ) || true ;
let d2 = false || gets();
let d3 = 4 || 5;


console.log(c1);
console.log(c2);
console.log(c3);
console.log(d1);
console.log(d2);
console.log(d3);



let varAny: any = null;

let add0 = 2 + 2;
let add1 = "2" + "2"
let add2 = "2" + varAny;
let add3 = varAny + "2";
let add4 = varAny + 2;
let add5 = 6 + varAny;
let add6 = "2" + 2;
let add7 = 2 + "2";


enum Const { PI = 3.14, E = 2.7818 }
enum State { OK = "ok", FAULT = "fail" }


let b1 = 7 ^ varAny;
let b2 = 7 | varAny;
let b3 = 7 & varAny;

let b4 = 7 << varAny;
let b5 = 7 >> varAny;
let b6 = 7 >>> varAny;

let b7 = varAny <<1;
let b8 = varAny >>2;
let b9 = varAny >>>3;

let b11 = 7 ^ Const.PI
let b12 = 7 | Const.E;
let b13 = 7 & Const.PI;

let b14 = 7 << Const.PI;
let b15 = 7 >> Const.E;
let b16 = 7 >>> Const.PI;

let b17 = Const.PI <<1;
let b18 = Const.E >>2;
let b19 = Const.PI >>>3;


let b31 = State.OK ^ 7
let b32 = 7 | State.FAULT;
let b33 = 7 & State.OK;

let b34 = 7 << State.OK;
let b35 = 7 >> State.FAULT;
let b36 = 7 >>> State.OK;

let b37 = State.FAULT <<1;
let b38 = State.OK >>2;
let b39 = State.FAULT >>>3;


let a000 = (k = 10,2+7);
