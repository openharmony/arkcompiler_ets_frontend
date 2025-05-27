/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
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

1..toString();
1.0.toString();
1. + 2.0 + 3.;

var i: number = 1;
var compactTest1 = i.toString();
var compactTest3 = 3 .toString();
var compactTest4 = 3    .toString();
var compactTest5 = 3	.toString();
var compactTest6 = 3.['toString']();
var compactTest7 = 3
  .toString();
var compactTest8 = new Number(4).toString();
var compactTest9 = 3. + 3.;
var compactTest10 = 0 /* comment */.toString();
var compactTest11 = 3. /* comment */.toString();
var compactTest12 = 3
  /* comment */ .toString();
var test122 = 3
/* comment */.toString();
var test1222 = 3

  .toString();
var compactTest13 = 3.
  /* comment */.toString();
var compactTest14 = 3
  // comment
  .toString();
var compactTest15 = 3.
  // comment
  .toString();
var compactTest16 = 3  // comment time
  .toString();
var compactTest17 = 3. // comment time again
  .toString();