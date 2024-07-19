/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

@Sendable
function D_sf():void {}
const Dv_sf = D_sf;

function D_nf():void {}
const Dv_nf = D_nf;

@Sendable
type D_Sft = ()=>void;
type Dv_Sft = D_Sft;

type D_Nft = ()=>void;
type Dv_Nft = D_Nft;

@Sendable
class D_Sc {}
class D_Nc {}


export {
  D_sf, Dv_sf, D_nf, Dv_nf, D_Sft, Dv_Sft, D_Nft, Dv_Nft, D_Sc, D_Nc,
  D_sf as AS_D_sf, Dv_sf as AS_Dv_sf, D_nf as AS_D_nf, Dv_nf as AS_Dv_nf,
  D_Sft as AS_D_Sft, Dv_Sft as AS_Dv_Sft, D_Nft as AS_D_Nft, Dv_Nft as AS_Dv_Nft,
  D_Sc as AS_D_Sc, D_Nc as AS_D_Nc
};
