/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

let Sendable = (x, y) => {}

// Sendable class inheritance
class NonSendableClass {}

@Sendable
class SendableClass {} // OK

@Sendable
class BadInheritance1 extends NonSendableClass {} // ERROR, extends non-sendable

class BadInheritance2 extends SendableClass {} // ERROR, no @Sendable decorator

@Sendable
class GoodInheritance extends SendableClass {} // OK

// Implement ISendable interface
interface ISendable {}

class BadSendableImpl implements ISendable {} // ERROR, no @Sendable decorator

class BadInterfaceImpl extends BadSendableImpl {} // OK, BadSendableImpl is not Sendable, as it has an error

@Sendable
class GoodSendableImpl implements ISendable {} // OK

@Sendable
class GoodInterfaceImpl extends GoodSendableImpl {} // OK

// Implement interface extending ISendable
interface ISendableExt extends ISendable {}

class BadInterfaceExtImpl implements ISendableExt {} // ERROR, no @Sendable decorator

@Sendable
class GoodInterfaceExtImpl implements ISendableExt {} // OK, class implements interface that extends ISendable