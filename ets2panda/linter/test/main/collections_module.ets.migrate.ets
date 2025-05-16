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







import { collections as definedCollections } from 'user_defined_worker'; //legal

function tesCollectionsUsage() {

  const collections1: Array<number> = new Array<number>();

  const collections2: number[] = new Array<number>();

  const collections3: number[] = new Array<number>();

  let collections4: Array<number>;

  const collections5: Array<number> = new Array<number>();

  let collections6: definedCollections.Array<number>; // legal

}
