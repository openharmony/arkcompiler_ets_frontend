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

class MyClassA {}

class MyClassB {
  name: string = ''
}

class MyClassC1 {}

class MyClassC2 extends MyClassC1 {}

class MyClassC3 extends MyClassC2 {}

class MyClassD extends MyClassC3 {}

class MyClassC4 extends MyClassD {}

interface IntfA {}

class MyClassE implements IntfA {}

@Observed
class MyClassF {}

class MyClassG {}

class MyClassH {}

class MyClassI {}

@Observed
class MyClassJ extends MyClassI {}

@Observed
class MyClassK extends MyClassJ {}

@Entry
@Component
struct Test {
  @State data1: number = 0
  @State data2: MyClassA = new MyClassA()
  @State data3: MyClassB = { name: "jack" }
  @State data4: MyClassC2 = new MyClassD()
  @State data5: IntfA = new MyClassE()
  @Prop data6: MyClassE = new MyClassE()
  @Prop data7: MyClassF = new MyClassF()
  @Prop data8: MyClassG | MyClassH | number = 0
  @Prop data9: MyClassJ = new MyClassK()
  @Provide selectedDate: Date = new Date('2021-08-08')
  @StorageLink('PropB') storageLink: MyClassA = new MyClassA()
  @LocalStorageLink('LinkB') localStorageLink: MyClassB = new MyClassB()
  @StorageProp('test') test1: MyClassC2 = new MyClassC3()
  @LocalStorageProp('test') test2: MyClassD = new MyClassD()

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