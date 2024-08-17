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

class __BaseClass {
  private __identifier: string;

  constructor(__identifier: string) {
    this.__identifier = __identifier;
  }
}
  
class __PersonDetails {
  public __first: string;
  private __last: string;
  protected __years: number;

  constructor(__first: string, __last: string, __years: number) {
    this.__first = __first;
    this.__last = __last;
    this.__years = __years;
  }
}
  
class __CustomTest {
  constructor(public __publicValue: number, private __privateValue: string, protected __protectedValue: number) {
    this.__publicValue = 1;
    this.__privateValue = "123";
    this.__protectedValue = 1;
  }
}


  