/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

class A {
    public name: string;
    static age: number;
    public Name(): string { return this.name }
    protected static setAge( age: number ) { A.age = age }
    private rename(newName: string ) { this.name = newName }
}

export class B extends A  {
    protected salary: number = 100;
    #work_hours = 40;
    #getSalary(): number { return this.salary }
}

abstract class C<T, U> extends B {
    test(): number { return 0;}
    abstract value():number;
}

class D {
    foo(n: number): void
    foo(n: number, s: string): void
    foo(...args: any[]):void {
    }
}
