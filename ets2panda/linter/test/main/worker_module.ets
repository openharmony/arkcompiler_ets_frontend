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

import { worker } from './oh_modules/@ohos.worker';

import { worker as workerAlias } from './oh_modules/@ohos.worker';

import { worker as kitWorker } from './oh_modules/@kit.ArkTS';

import { worker as definedWorker } from 'user_defined_worker'; //legal

export { worker } from './oh_modules/@ohos.worker';

function testWorkerUsage() {

  const worker1: worker.ThreadWorker = new worker.ThreadWorker('script.js');

  const worker2 = new workerAlias.ThreadWorker('script.js');

  const worker3 = new kitWorker.ThreadWorker('script.js');

  let worker4: workerAlias.ThreadWorker('script.js');

  const worker5: workerAlias.ThreadWorker = new workerAlias.ThreadWorker('script.js');

  let worker6: definedWorker.ThreadWorker('script.js'); // legal

}