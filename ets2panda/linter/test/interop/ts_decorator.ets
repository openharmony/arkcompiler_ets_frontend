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

import {MyClassDecorator, MyClassDecorator2} from "./oh_modules/ts_decorator"
import { MyDecorator } from "./oh_modules/ets_decorator";

@MyClassDecorator
class K {}

@Entry //legal
class X {}

@MyDecorator //legal
class Y {}

@MyClassDecorator2
class Z {}

class Example {
  @MyClassDecorator2  //legal
  doSomething() {}
}
