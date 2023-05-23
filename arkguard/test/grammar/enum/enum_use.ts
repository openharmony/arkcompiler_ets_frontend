/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import assert = require('assert');

enum ANIMAL {
  CAT,
  DOG,
  GOOSE,
  DUCK,
}

const favoriteType1 = ANIMAL.CAT;
assert.strictEqual(favoriteType1, ANIMAL.CAT);

const favoriteType2 = ANIMAL.DOG;
assert.strictEqual(favoriteType2, ANIMAL.DOG);

const favoriteType3 = ANIMAL.GOOSE;
assert.strictEqual(favoriteType3, ANIMAL.GOOSE);

const favoriteType4 = ANIMAL.DUCK;
assert.strictEqual(favoriteType4, ANIMAL.DUCK);
