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

declare module 'ambient-module';

class C {}

declare module '*!text' {
  const content: string;
  export default content;
}

declare module 'json!*' {
  const value: any;
  export default value;
}

declare module 'library/*';

declare module 'abc' {
  export function f(): void;
}

declare namespace abc2 {
  export function f(): void;
  function foo(): void;
  export { foo }
}
