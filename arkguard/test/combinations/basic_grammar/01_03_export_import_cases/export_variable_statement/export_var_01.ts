/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import assert from "assert";

export var var1 = 1;
export var { } = {}
export var { var2 } = { var2: 2 }
export var { ...vals } = { val3: 3, val4: 4, val5: 5 }
export var { var6, ...varn } = { var6: 6, var7: 7, var8: 8 };
export var { var9, "var10": var10, ...varo } = { var9: 9, var10: 10, var11: 11 };
export var { var12, ['var13']: var13Alis, ...varp } = { var12: 12, var13: 13, var14: 14 }
let var16Cons: number = 16;
export var { var15, ["var16"]: var16, ...varq } = { var15: 15, var16: [var16Cons], var17: 17 }
export var { ["var" + "18"]: var18, var19 } = { ["var" + "18"]: 18, var19: 19 };

assert(var1 === 1);
assert(var2 === 2);
assert(vals.val3 === 3);
assert(vals.val4 === 4);
assert(vals.val5 === 5);
assert(var6 === 6);
assert(varn.var7 === 7);
assert(varn.var8 === 8);
assert(var9 === 9);

assert(var10 === 10);
assert(varo.var11 === 11);
assert(var12 === 12);
assert(var13Alis === 13);
assert(varp.var14 === 14);
assert(var15 === 15);
assert(var16.toString() === "16");
assert(varq.var17 === 17);
assert(var18 === 18);
assert(var19 === 19);

namespace ns1 {
  export var { var20, ["var" + "21"]: var21, ...varr } = { var20: 20, ["var" + "21"]: 21, var22: 22 };
  assert(var20 === 20);
  assert(var21 === 21);
  assert(varr.var22 === 22);
}
assert(ns1.var20 === 20);
assert(ns1.var21 === 21);
assert(ns1.varr.var22 === 22);


export var [] = []
export let [,] = [,]
export var [ele1, ele2] = [1, 2];
export var [ele3, , ele5] = [3, 4, 5, 6];
export var [...eles1] = [7, 8, 9];
export var [ele10, ...eles2] = [10, 11, 12];
export var [, ...eles3] = [13, 14, 15]


assert(ele1 === 1);
assert(ele2 === 2);
assert(ele3 === 3);
assert(ele5 === 5);
assert(eles1[0] === 7);
assert(eles1[1] === 8);
assert(eles1[2] === 9);
assert(ele10 === 10);
assert(eles2[0] === 11);
assert(eles2[1] === 12);
assert(eles3[0] === 14);
assert(eles3[1] === 15);

namespace ns2 {
  export var [ele13, { ele14 }] = [13, { ele14: 14 }, 15]
  assert(ele13 === 13);
  assert(ele14 === 14);
}
assert(ns2.ele13 === 13);
assert(ns2.ele14 === 14);