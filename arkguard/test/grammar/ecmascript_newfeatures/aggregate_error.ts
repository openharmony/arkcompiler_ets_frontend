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

const Promise1 = new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('Promise 1 error')), 1000);
});
const Promise2 = new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('Promise 2 error')), 2000);
});
const Promise3 = new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('Promise 3 error')), 3000);
});

Promise.any([Promise1, Promise2, Promise3])
    .then((value) => {
    })
    .catch((error) => {
        if (error instanceof AggregateError) {
            assert(error.errors[0].message === 'Promise 1 error', 'success');
            assert(error.errors[1].message === 'Promise 2 error', 'success');
            assert(error.errors[2].message === 'Promise 3 error', 'success');
        }
    })
