/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

function main(): void {
    let preA : a;

    type a = Double;

    let a : a;

    a = 1.1;
}

function foo(){

    switch (1) {
        case 0:     
            type dsa = Double;
            let dsa : dsa;
            break
        case 1:
            let asd: asd;
            break
        default :
            type asd = number;
    }

    {
        let asd : asd;
        type asd = number;
        type dsa = Double;
        let dsa : dsa;
    }

    while (true) {
        let asd : asd;
        type asd = Object;
        type dsa = Double;
        let dsa : dsa;
        break;
    }

    for (let k: int = 0; k < 10; k++) {
        let asd : asd;
        type asd = Double;

        type dsa = Double;
        let dsa : dsa;
    }

    try {
        let asd : asd;
        type asd = Double;

        type dsa = Double;
        let dsa : dsa;
    } catch (e){
        let asd : asd;
        type asd = Double;

        type dsa = Double;
        let dsa : dsa;
    }

}
