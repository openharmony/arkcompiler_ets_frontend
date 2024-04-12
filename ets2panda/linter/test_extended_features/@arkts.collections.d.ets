/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable low or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

declare namespace collections {
    class Array<T> {
        [k: number]: T; // Ok
        [s: string]: T; // Illegal
    }

    class Set<T> {
        [k: number]: T; // Illegal
        [s: string]: T; // Illegal
    }

    class Int8Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class Uint8Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class Uint8ClampedArray {
        constructor(length: number);

        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Int16Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class Uint16Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class Int32Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class Uint32Array {
        constructor(length: number);

        [k: number]: number; // Ok
        [s: string]: number; // Illegal
    }

    class BigInt64Array {
        constructor(length: number);

        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class BigUint64Array {
        constructor(length: number);

        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Float32Array {
        constructor(length: number);

        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Float64Array {
        constructor(length: number);

        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }
}

declare namespace utils {
    class Array<T> {
        [k: number]: T; // Illegal
        [s: string]: T; // Illegal
    }

    class Set<T> {
        [k: number]: T; // Illegal
        [s: string]: T; // Illegal
    }

    class Int8Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Uint8Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Uint8ClampedArray {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Int16Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Uint16Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Int32Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Uint32Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class BigInt64Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class BigUint64Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Float32Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }

    class Float64Array {
        [k: number]: number; // Illegal
        [s: string]: number; // Illegal
    }
}

export default collections;