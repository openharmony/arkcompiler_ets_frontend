/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

interface ClockInterface {
    tick(): void;
}
    
class DigitalClock implements ClockInterface {
    constructor(h: number, m: number) {}
    tick() {
        console.log("beep beep");
    }
}
    
class AnalogClock implements ClockInterface {
    constructor(h: number, m: number) {}
    tick() {
        console.log("tick tock");
    }
}

function constructorSignature(): void {
    interface ClockConstructor {
        new (hour: number, minute: number): ClockInterface;
    }
    
    function createClock(
        ctor: ClockConstructor,
        hour: number,
        minute: number
    ): ClockInterface {
        return new ctor(hour, minute);
    }

    let digital = createClock(DigitalClock, 12, 17);
    let analog = createClock(AnalogClock, 7, 32);
}

function constructorType(): void {
    function createClock(
        ctor: new (hour: number, minute: number) => ClockInterface, 
        h: number,
        m: number
    ): ClockInterface {
        return new ctor(h, m);
    }

    let digital = createClock(DigitalClock, 16, 30);
    let analog = createClock(AnalogClock, 23, 45);
}