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

function mergeObjects<T, U>(primary: T, secondary: U): T & U {
  const merged = {} as T & U;

  for (const prop in primary) {
    merged[prop] = primary[prop] as any;
  }

  for (const prop in secondary) {
    if (!Object.prototype.hasOwnProperty.call(merged, prop)) {
      merged[prop] = secondary[prop] as any;
    }
  }
  return merged;
}

class Human {
  constructor(public username: string) {}
}

interface LoggingCapability {
  writeLog(): void;
}

class TerminalLogger implements LoggingCapability {
  writeLog(): void {
    console.log('Jim');
  }
}

const user = mergeObjects(new Human('Jim'), new TerminalLogger());
const currentUser = user.username;

assert(currentUser === 'Jim', 'success');
