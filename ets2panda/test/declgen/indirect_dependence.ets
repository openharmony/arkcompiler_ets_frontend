/**
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
class A {}
class C {}
class D {}

export class B {
    a: A = new A();
}

export function foo(c: C) {
    return 123;
}

export function foo1() {
    return new D();
}

export type Point3 = Point2;

type Point2 = Point1;
type Point1 = Point;
declare class Point {
  public x: double;
  
  public y: double;
  
  public constructor();
  
}