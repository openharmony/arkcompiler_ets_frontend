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

class C {
  constructor(x: number, y: string);
  constructor(s: string);
  constructor(xs: any, y?: any) {}
}
let c = new C(10, 'foo');

/* @@? 17:14 Error TypeError: Only abstract or native methods can't have body.  */
/* @@? 19:3 Error TypeError: No matching call signature for constructor  */
/* @@? 19:19 Error TypeError: Cannot find type 'any'.  */
/* @@? 19:28 Error TypeError: Cannot find type 'any'.  */

