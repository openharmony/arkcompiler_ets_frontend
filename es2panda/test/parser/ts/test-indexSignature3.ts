/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


interface I1 {
    [key: (string | (number | number))]: boolean
  }

  interface I2 {
    [key: boolean & number extends string ? number : symbol]: boolean
  }

  type A = { a: number }

  interface I3 {
    [key: A["a"]]: boolean
  }

  interface I4 {
    [key: string & string]: boolean
  }

  interface I5 {
    [key: string | & string]: boolean
  }
