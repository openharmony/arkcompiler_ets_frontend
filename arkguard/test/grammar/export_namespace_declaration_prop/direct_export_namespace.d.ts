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

export declare namespace ns1 {
    function foo1(): void;
    class className1 {
        prop11: number;
    }
    interface interName1 {
    }
}


export declare namespace ns2 {
    export function foo2(): void;
    export class className2 {
        prop21: number;
        prop22: interName1 | undefined;
    }
    interface interName1 {
    }
    export interface interName2 {
    }
    export {};
}

export declare namespace ns3 {
    function foo3(): void;
    class className3 {
        31: number;
        prop22: interName1 | undefined;
    }
    interface interName1 {
    }
}

export declare namespace ns4 {
    function foo4(): void;
    class className4 {
        [41]: number;
    }
}

export declare namespace ns5 {
    function foo5(): void;
    class className5 {
        [`55`]: string;
    }
    interface interName5 {
    }
}

export declare namespace ns12 {
    function foo12(): void;
    class className12 {
        ['122']: string;
    }
    interface interName12 {
    }
}

export declare namespace ns6 {
    function foo6(): void;
    class className6 {
        #private;
    }
    interface interName6 {
    }
}