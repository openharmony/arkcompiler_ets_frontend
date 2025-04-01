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

import { MyClassB, MyClassD } from './'

class MyClassA {
}

class MyClassC {
}

@Observed
class MyClassE {
}

AppStorage.setOrCreate('PropA', 47);
AppStorage.setOrCreate('PropB', new MyClassC());
let storage = new LocalStorage();
storage.setOrCreate('LinkA', 48);
storage.setOrCreate('LinkB', new MyClassA());

@Entry
@Component
struct Test {
  @State data1: number = 0
  @State data2: MyClassA = 0
  @State data3: MyClassB | string = 0
  @State data4: undefined | string | MyClassC | MyClassD = 0
  @State data5: MyClassE = 0
  @Prop data6: MyClassA = 0
  @Provide selectedDate: Date = new Date('2021-08-08')
  @StorageLink('PropA') storageLink1: number = 1
  @StorageLink('PropB') storageLink2: MyClassC = new MyClassC()
  @LocalStorageLink('LinkA') localStorageLink1: number = 1
  @LocalStorageLink('LinkB') localStorageLink2: MyClassA = new MyClassA()
  @StorageProp('test') test1: MyClassB = 0;
  @LocalStorageProp('test') test2: MyClassB = 0;

  build() {

  }
}

@Component
struct MyComponent {
  @Link data2: MyClassA
  @Consume selectedDate: Date

  build() {

  }
}