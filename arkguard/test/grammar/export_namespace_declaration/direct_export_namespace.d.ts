/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export declare namespace ns11 {
    function foo11(): void;
    class className11 {
        prop11: number;
    }
    interface interName11 {
    }
}


export declare namespace ns12 {
    export function foo12(): void;
    export class className12 {
        prop21: number;
        prop22: interName11 | undefined;
    }
    interface interName11 {
    }
    export interface interName12 {
    }
    export {};
}

export declare namespace ns13 {
    function foo13(): void;
    class className13 {
        31: number;
        prop22: interName13 | undefined;
    }
    interface interName13 {
    }
}

export declare namespace ns14 {
    function foo14(): void;
    class className14 {
        [41]: number;
    }
}

export declare namespace ns15 {
    function foo15(): void;
    class className15 {
        [`55`]: string;
    }
    interface interName15 {
    }
}

export declare namespace ns12 {
    function foo12(): void;
    class className12 {
        ['12']: string;
    }
    interface interName12 {
    }
}

export declare namespace ns16 {
    function foo16(): void;
    class className16 {
        #private;
    }
    interface interName16 {
    }
}