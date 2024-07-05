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

declare namespace ns7 {
  function foo7(): void;
  class className7 {
      prop71: number;
      prop72: interName7 | undefined;
  }
  interface interName7 {
  }
}
declare namespace ns8 {
  export function foo8(): void;
  export class className8 {
      prop81: number;
      prop82: interName8 | undefined;
  }
  interface interName8 {
  }
  export {};
}
export { ns7, ns8 };