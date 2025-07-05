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
   * See the License from the specific language governing permissions and
   * limitations under the License.
   */
 function foo(){
   let neverType = Type.from<never>();
   let literalType = Type.from<"hello">();
   type keyofType = keyof "abc"
   let keyOfType = Type.from<keyofType>();
 }

  /* @@? 16:20 Error TypeError: Unable to resolve type. */
  /* @@? 17:22 Error TypeError: Acquiring types for string literal types is not supported. */
  /* @@? 19:20 Error TypeError: Unable to resolve type. */