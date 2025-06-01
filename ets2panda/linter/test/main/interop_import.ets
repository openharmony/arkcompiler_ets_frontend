/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

import { CPreview } from "./.preview/preview_import";
import { CBuild } from "./build/build_import";
import { CNode } from "./node_modules/node_import";
import { COh } from "./oh_modules/oh_import";
import { CGood } from "./ignore_files/good";
import { CHvigor } from "./ignore_files/hvigorfile";
import { Cjs2 } from "./node_modules/2";
import { Cjs1 } from "./node_modules/node_lib/1";

CPreview.prototype;
CBuild.prototype;
CNode.prototype;
COh.prototype;
CGood.prototype;
CHvigor.prototype;
Cjs1.prototype;
Cjs2.prototype;

class B {
  f: number = 1;
}
let CJS1: Cjs1 = new Cjs1();
let cjs1 = new Cjs1();
let f1: B = cjs1;
let CJS2: Cjs2 = new Cjs2();
let cjs2 = new Cjs2();
let f2: B = cjs2;
