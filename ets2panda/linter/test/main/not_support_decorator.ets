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

function decorateKlass(target: Object) {
  console.log("decorateKlass")
}

@decorateKlass
class Person {
    age: number = 12
}

function customDecorator(target: Object) {
    console.log("Custom decorator applied");
}

@customDecorator
class User {
    name: string = "John";
    age: number = 30;
}

function decoratorOne(target: Object) {
    console.log("Decorator one applied");
}

function decoratorTwo(target: Object) {
    console.log("Decorator two applied");
}

@decoratorOne
@decoratorTwo
class Product {
    id: number = 1;
    price: number = 9.99;
}

function innerDecorator(target: Object) {
    console.log("Inner decorator applied");
    return target;
}

function outerDecorator(target: Object) {
    return innerDecorator(target);
}

@outerDecorator
class Order {
    orderNumber: string = "12345";
    status: string = "Pending";
}

@outerDecorator()
class Employee {
    employeeId: number = 1001;
    department: string = "HR";
}

@Entry
class EntryTest {
    employeeId: number = 1001;
    department: string = "HR";
}

@Component
class ComponentTest {
    employeeId: number = 1001;
    department: string = "HR";
}

@Sendable
class SendableTest {
    employeeId: number = 1001;
    department: string = "HR";
}
