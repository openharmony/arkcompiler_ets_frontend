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

/**
 * we should avoid get an obfuscated name as f2, g2, h2
 */
type testType1 = number;
declare class testClass {}
declare function foo()
declare namespace ns{}
type testType2 = number;
declare module "testModule" {
  import { f2, g2, h2 } from "fs";
  let var1: testType1;
  let var2: testType2;
  let var3: testClass;
}