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
'use static'

let arkTsMod = await import('./test_files/dummy_arkts1_file');
let tsModule  = await import('./test_files/dummy_ts_file');
let jsModule = await import('./test_files/dummy_js_file');

function main(): void {
  import('./test_files/dummy_ts_file').then((m) => {
    console.log(m.Data.name)
  })
}
