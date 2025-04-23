/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

interface ObjectConstructor {
    new (value?: any): Object;
    (): any;
    (value: any): any;

    readonly prototype: Object;

    getPrototypeOf(o: any): any;

    getOwnPropertyDescriptor(o: any, p: PropertyKey): PropertyDescriptor | undefined;

    getOwnPropertyNames(o: any): string[];

    create(o: object | null): any;

    create(o: object | null, properties: PropertyDescriptorMap & ThisType<any>): any;

    defineProperty<T>(o: T, p: PropertyKey, attributes: PropertyDescriptor & ThisType<any>): T;

    defineProperties<T>(o: T, properties: PropertyDescriptorMap & ThisType<any>): T;

    seal<T>(o: T): T;

    freeze<T extends Function>(f: T): T;

    freeze<T extends { [idx: string]: U | null | undefined | object; }, U extends string | bigint | number | boolean | symbol>(o: T): Readonly<T>;

    freeze<T>(o: T): Readonly<T>;

    preventExtensions<T>(o: T): T;

    isSealed(o: any): boolean;

    isFrozen(o: any): boolean;

    isExtensible(o: any): boolean;

    keys(o: object): string[];
}

declare var Object: ObjectConstructor;

interface String {
    toString(): string;
    charAt(pos: number): string;
    charCodeAt(index: number): number;
    concat(...strings: string[]): string;
    indexOf(searchString: string, position?: number): number;
    lastIndexOf(searchString: string, position?: number): number;
    localeCompare(that: string): number;
    match(regexp: string | RegExp): RegExpMatchArray | null;
    replace(searchValue: string | RegExp, replaceValue: string): string;
    replace(searchValue: string | RegExp, replacer: (substring: string, ...args: any[]) => string): string;
    search(regexp: string | RegExp): number;
    slice(start?: number, end?: number): string;
    split(separator: string | RegExp, limit?: number): string[];
    substring(start: number, end?: number): string;
    toLowerCase(): string;
    toLocaleLowerCase(locales?: string | string[]): string;
    toUpperCase(): string;
    toLocaleUpperCase(locales?: string | string[]): string;
    trim(): string;
    readonly length: number;
    substr(from: number, length?: number): string;
    valueOf(): string;
    readonly [index: number]: string;
}

interface StringConstructor {
    new (value?: any): String;
    (value?: any): string;
    readonly prototype: String;
    fromCharCode(...codes: number[]): string;
}

declare var String: StringConstructor;

interface Boolean {
    valueOf(): boolean;
}

interface BooleanConstructor {
    new (value?: any): Boolean;
    <T>(value?: T): boolean;
    readonly prototype: Boolean;
}

declare var Boolean: BooleanConstructor;

interface Number {
    toString(radix?: number): string;
    toFixed(fractionDigits?: number): string;
    toExponential(fractionDigits?: number): string;
    toPrecision(precision?: number): string;
    valueOf(): number;
}

interface NumberConstructor {
    new (value?: any): Number;
    (value?: any): number;
    readonly prototype: Number;

    /** The largest number that can be represented in JavaScript. Equal to approximately 1.79E+308. */
    readonly MAX_VALUE: number;

    /** The closest number to zero that can be represented in JavaScript. Equal to approximately 5.00E-324. */
    readonly MIN_VALUE: number;

    /**
     * A value that is not a number.
     * In equality comparisons, NaN does not equal any value, including itself. To test whether a value is equivalent to NaN, use the isNaN function.
     */
    readonly NaN: number;

    /**
     * A value that is less than the largest negative number that can be represented in JavaScript.
     * JavaScript displays NEGATIVE_INFINITY values as -infinity.
     */
    readonly NEGATIVE_INFINITY: number;

    /**
     * A value greater than the largest number that can be represented in JavaScript.
     * JavaScript displays POSITIVE_INFINITY values as infinity.
     */
    readonly POSITIVE_INFINITY: number;
}

declare var Number: NumberConstructor;