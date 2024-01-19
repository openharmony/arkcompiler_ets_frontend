/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

export declare class Something { beep(): number }

export declare class SomethingFactory {
    private constructor();

    public static getInstance(): SomethingFactory;

    public create1<T extends Something>(arg: { new(): T }): T;
    public create2<T extends Something>(arg: { o: { new(): T } }): T;
    public create3<T extends Something>(arg: () => { new(): T }): T;
    public create4<T extends Something>(arg: Function): T;
}

export declare class SomethingBar extends Something { }

export declare class Bar<T extends Something> {
    constructor(arg: { new(): T });
}

export class Select<Model> {
    public from(cls: any) {
        return this;
    }

    // we intentionally omit generic argument of 'Select', see #14228
    public eq(name: string): Select {
        return this;
    }

    public query(cls: any): Promise<any> {
        return cls.foo();
    }
}