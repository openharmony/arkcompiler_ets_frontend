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

declare namespace ns17 {
  function foo17(): void;
  class className17 {
      prop71: number;
      prop72: interName17 | undefined;
  }
  interface interName17 {
  }
}
declare namespace ns18 {
  export function foo18(): void;
  export class className18 {
      prop81: number;
      prop82: interName18 | undefined;
  }
  interface interName18 {
  }
  export {};
}
export { ns17, ns18 };