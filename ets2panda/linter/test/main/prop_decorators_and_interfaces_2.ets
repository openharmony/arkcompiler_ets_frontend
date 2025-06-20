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

class MyClassA {
    
}

let para: Record<string, number> = { 'PropA': 47 }
let storage: LocalStorage = new LocalStorage(para)
let prop1 = storage.prop<number>('PropA')
let prop2 = storage.prop<MyClassA>('PropA')
let prop3 = storage.prop<number | MyClassA>('PropA')
let prop4: SubscribedAbstractProperty<string> = storage.prop('PropA')
let prop5: SubscribedAbstractProperty<MyClassA> = storage.prop('PropA')
let prop6: SubscribedAbstractProperty<MyClassA | string> = storage.prop('PropA')

AppStorage.SetOrCreate('PropB', 46)
let prop7 = AppStorage.prop<number>('PropB')
let prop8 = AppStorage.prop<MyClassA>('PropB')
let prop9 = AppStorage.prop<number | MyClassA>('PropB')
let prop10: SubscribedAbstractProperty<string> = AppStorage.prop('PropB')
let prop11: SubscribedAbstractProperty<MyClassA> = AppStorage.prop('PropB')
let prop12: SubscribedAbstractProperty<MyClassA | string> = AppStorage.prop('PropB')

@Entry
@Component
struct MyComponent {

    aboutToAppear(): void {
        let storage = LocalStorage.getShared()
        let prop1 = storage.prop<MyClassA>('PropA')
        let prop2: SubscribedAbstractProperty<MyClassA> = storage.prop('PropA')
    }

    build() {
    }
}