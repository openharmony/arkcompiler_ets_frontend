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

abstract class Y {
    abstract getDataByName(name: string | number, albumUri: string): Promise<void>;
}

class X extends Y {
    async getDataByName(name: string, albumUri: string): Promise<undefined> {
        return;
    }
}

abstract class B {
    abstract getDataByName(name: string | number, albumUri: string): Promise<undefined> | Promise<void>;
}

class A extends B {
    async getDataByName(name: string | number | boolean, albumUri: string): Promise<undefined> { //Legal
        return undefined;
    }
}

abstract class W {
    abstract getDataByName(name: string | number, albumUri: string): Promise<void>;
}

class Q extends W {
    async getDataByName(name: string | number, albumUri: string | number): Promise<undefined> {
        return;
    };
}

abstract class BaseClass3 {
    abstract compute(value: string): string;
}

class IncorrectWiderReturn extends BaseClass3 {
    compute(value: string): string | number {
        return value.length > 5 ? value : 0;
    }
}

abstract class BaseClass4 {
    abstract setValues(x: string | number, y: boolean | number): void;
}

class IncorrectMultipleParamMismatch extends BaseClass4 {
    setValues(x: string, y: boolean): void {
        console.log(x, y);
    }
}

abstract class BaseClass5 {
    abstract transform(data: number | string): number;
}

class IncorrectBothMismatch extends BaseClass5 {
    transform(data: number): number | string {
        return data > 10 ? data : "too small";
    }
}

//legal
abstract class BaseClass {
    abstract getData(a: string | number): string | number;
}

class CorrectWiderParam extends BaseClass {
    getData(a: string | number | boolean): string | number {
        return typeof a === 'boolean' ? 0 : a;
    }
}

class CorrectNarrowerReturn extends BaseClass {
    getData(a: string | number): string {
        return typeof a === 'number' ? a.toString() : a;
    }
}

class CorrectBothWiderParamNarrowReturn extends BaseClass {
    getData(a: string | number | boolean): string {
        return String(a);
    }
}


