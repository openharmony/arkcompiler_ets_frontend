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

import type { D_Sft, D_Nft } from './sendable_function_dependencie';
import {
  D_sf, Dv_sf, D_nf, Dv_nf, Dv_Sft, Dv_Nft, D_Sc, D_Nc,
  D_sf as AS_D_sf, Dv_sf as AS_Dv_sf, D_nf as AS_D_nf, Dv_nf as AS_Dv_nf,
  D_Sft as AS_D_Sft, Dv_Sft as AS_Dv_Sft, D_Nft as AS_D_Nft, Dv_Nft as AS_Dv_Nft,
  D_Sc as AS_D_Sc, D_Nc as AS_D_Nc
} from './sendable_function_dependencie';

// -------------------- check sendable-function declaration -------------------- //
@Sendable 
function sf():void {} // OK
@Sendable 
function stf<T>(p:T):T {
  return p;
} // OK
@Sendable 
@Other  // ERROR
function sf2():void {}


// check overloading
@Sendable 
function sf3():void; // OK
@Sendable 
function sf3():void;

@Sendable 
function sf3():void {}

@Sendable 
function sf4():void;
@Sendable
function sf4():void; // ERROR
@Sendable 
function sf4():void {}

@Sendable 
function sf5():void;

@Sendable 
@Other  // ERROR
function sf5():void;

@Sendable 
function sf5():void {}

function nf():void {}

// -------------------- check sendable-typealias declaration -------------------- //
@Sendable 
type Sft = () => void; // OK
@Sendable 
type Sft2<T> = () => void; // OK
@Sendable 
type Sft3 = <T>(p:T) => T; // OK
@Sendable 
@Other // ERROR
type Sft4 = () => void; 
@Sendable 
type Sft5 = number; // ERROR
@Sendable 
type Sft6 = Sft; // ERROR
type Sft7 = () => void;

@Sendable 
type Sft8 = Sft4; // ERROR

type Nft = ()=>void;

// -------------------- check sendable-function closure -------------------- //
@Sendable 
class Sc {}
class Nc {}

@Sendable 
class SendableClassClosure {
  constructor() {
    const a1:Sft = sf; // OK
    const a2:Nft = nf; // ERROR
    const a3:Sc = new Sc(); // OK
    const a4:Nc = new Nc(); // ERROR

    const b1:D_Sft = D_sf; // OK
    const b2:D_Nft = D_nf; // OK
    const b3:D_Sc = new D_Sc(); // OK
    const b4:D_Nc = new D_Nc(); // OK
  }

  @nf
  handle() {}
}

@Sendable 
@nf
function SendableFunctionClosure() {
  const a1:Sft = sf; // OK
  const a2:Nft = nf; // ERROR
  const a3:Sc = new Sc(); // OK
  const a4:Nc = new Nc(); // ERROR
  const b1:D_Sft = D_sf; // OK
  const b2:D_Nft = D_nf; // OK
  const b3:D_Sc = new D_Sc(); // OK
  const b4:D_Nc = new D_Nc(); // OK
}

namespace ns {
  @Sendable
  function sf():void;
  @Sendable
  function sf():void {}
}



// -------------------- check sendable-typealias is sendaboe-data-type -------------------- //


// check property
@Sendable 
class Sc2<T> {
  p1: Sft = sf; // OK
  p2: D_Nft = sf; // ERROR
}
// check genericity
new Sc2<Sft>();
new Sc2<D_Nft>(); // ERROR

// -------------------- check sendable-function cannot operation property --------------------//
sf.prop = 1; // ERROR
D_nf.prop = 1; // OK
D_sf.prop = 1; // ERROR
AS_D_sf.prop = 1;// ERROR

// -------------------- check sendable-function assignment --------------------//

@Sendable
function stf1<T>(p:T):T {return p;};
function ntf1<T>(p:T):T {return p};
//
const of1 = ()=>{};
//
@Sendable
type Stft1 = <T>(p:T)=>T;
@Sendable
type Stft2<T> = ()=>void;
//
type Nft1 = ()=>void;
type Nft2 = ()=>number;
type Ntft1 = <T>(p:T)=>T;
type Ntft2<T> = ()=>void;
//
type U_Sft1 = Sft | D_Sft;
type U_Sft2 = Sft | Stft1;
type U_Nft1 = Nft1 | Nft2;
type U_Nft2 = Nft1 | Ntft1;
type U_ft1 = Sft | Nft1;
type U_ft2 = Sft | Stft1| Nft1 | Ntft1;
//
type TU_Sft1<T> = Sft | D_Sft;
type TU_Sft2<T> = Sft | Stft1 | Stft1 ;
type TU_Nft1<T> = Nft1 | Nft2;
type TU_Nft2<T> = Nft1 | Ntft1| Ntft2<string>;
type TU_ft1<T> = Sft | Stft1 | Nft1 | Ntft1;
//
type DU_Sft1 = U_Sft1 | U_Sft2;
type DU_Sft2<T> = DU_Sft1 | TU_Sft1<T>;
type DU_Sft3<T> = DU_Sft2<T> | TU_Sft2<T>;
type DU_Nft<T> = DU_Sft3<T> | TU_Nft2<T>;
// normal
const a1: Sft = sf; // OK
const a2: Sft = nf; // ERROR
const a3: Sft = of1; // ERROR
const a4: Nft1 = nf; // OK
const a5: Sft = a1; // OK
const a6: Sft = a4; // ERROR
// generic
const b1: Stft1 = stf1; // OK
const b2: Stft1 = ntf1; // ERROR
const b3: Ntft1 = ntf1; // OK
const b4: Stft1 = b1; // OK
const b5: Stft1 = b3; // ERROR
// unite
const f1: U_ft1 = sf; // OK
const f2: U_ft2 = stf1; // OK
const f3: U_ft1 = nf; // ERROR
const f4: U_ft2 = ntf1; // ERROR
const d1: U_Sft1 = sf; // OK
const d2: U_Sft1 = nf; // ERROR
const d3: U_Sft1 = of1; // ERROR
const d4: U_Nft1 = sf; // OK
const d5: U_Nft1 = nf; // OK
const d6: U_Nft1 = of1; // OK
const d7: U_Sft1 = d1; // OK
const d18: U_Sft1 = d4; // ERROR
const d9: U_Sft1 = f1; // ERROR
// const d10: U_Sft1 = f2; // ERROR
const e1: U_Sft2 = stf1; // OK
const e2: U_Sft2 = ntf1; // ERROR
const e3: U_Nft2 = ntf1; // OK
const e4: U_Sft2 = e1; // OK
const e5: U_Sft2 = e3; // ERROR
const e6: U_Sft2 = f1; // ERROR
const e7: U_Sft2 = f2; // ERROR
// unite & generic
const g1: TU_ft1<number> = sf; // OK
const g2: TU_ft1<number> = stf1; // OK
const g3: TU_ft1<number> = nf; // ERROR
const h1: TU_Sft1<number> = sf; // OK
const h2: TU_Sft1<number> = nf; // ERROR
const h3: TU_Sft1<number> = of1; // ERROR
const h4: TU_Nft1<number> = nf; // OK
const h5: TU_Sft1<number> = h1; // OK
const h6: TU_Sft1<number> = h4; // ERROR
const h7: TU_Sft2<number> = stf1; // OK
const h8: TU_Sft2<number> = ntf1; // ERROR
