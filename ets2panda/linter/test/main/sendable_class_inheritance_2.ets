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

import { lang } from './@arkts.lang';

@Sendable
class GoodA implements lang.ISendable {}

class BadA implements lang.ISendable {} // Fixable

interface B extends lang.ISendable {}

@Sendable
class GoodB implements B {}

class BadB implements B {} // Fixable

@Sendable
class C {}

@Sendable
class GoodC extends C {}

class BadC extends C {} // Fixable

class BadC2 extends C implements lang.ISendable {} // Fixable

class D {}

@Sendable
class BadD extends D {} // Not fixable

class GoodD extends D {}