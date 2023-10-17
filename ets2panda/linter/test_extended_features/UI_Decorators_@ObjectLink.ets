/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

export {}

@Observed
class ClassA {
    public a: number;
    constructor(a?: number) {
        this.a = a ? a : 0;
    }
}

@Component
struct Child {
    @ObjectLink objLink: ClassA;

    build() {
        Row({ space: 20 }) {
            Text(`objLink: ${JSON.stringify(this.objLink)}`)
            Button(`a++`)
                .onClick(() => { this.objLink.a++; })
        }
        .border({ width: 3, color: Color.Red })
    }
}

@Entry
@Component
struct Parent {
    @State arr: ClassA[] = [new ClassA(123), new ClassA(222), new ClassA(300)];
    @State single: ClassA = new ClassA(1);

    build() {
        Column({ space: 20 }) {
            Row({ space: 10 }) {
                Text(`arr: ${JSON.stringify(this.arr)}`)
                Button(`arr[1].a++`)
                .onClick(() => { this.arr[1].a++; })
                Button(`assign`)
                .onClick(() => { this.arr[1] = new ClassA(10*this.arr[1].a); })
            }

            Row({ space: 10 }) {
                Text(`single: ${JSON.stringify(this.single)}`)
                Button(`single.a++`)
                .onClick(() => { this.single.a++; })
                Button(`assign`)
                .onClick(() => { this.single = new ClassA(10*this.single.a); })
            }
            Child({ objLink: this.arr[1] })
            Child({ objLink: this.single})
        }
        .width('100%')
    }
}
