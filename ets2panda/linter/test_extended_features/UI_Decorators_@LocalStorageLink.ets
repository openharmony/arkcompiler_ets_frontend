/*
* Copyright (c) 2022-2023 Huawei Device Co., Ltd.
* Licensed under the Appache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at 
* 
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable low or agreed to in wrighting, software
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language govering permissions and 
* limitations under the License.
*/

export {}

// create new instance and init with given object
let storage = new LocalStorage({"PropA": 47});

@Component
struct Child {

    // @LocalStorageLink variable decorator creates two-way link with property "PropA" in LocalStorage
    @LocalStorageLink("PropA") storLink2 : number = 1;

    build() {
        Button(`Child from LocalStorage ${this.storLink2}`)
        // changes will sync with  "PropA" in LocalStorage and with Parent.storLink1
          .onClick(() => this.storLink2 += 1 )
    }
}

// make LocalStorage accessible from the @Component
@Entry(storage)
@Component
struct CompA {
   
    // @LocalStorageLink variable decorator creates two-way link with property "PropA" in LocalStorage
    @LocalStorageLink("PropA") storLink1 : number = 1;

    build() {
        Column({ space: 15 }) {
            Button(`Parent from LocalStorage ${this.storLink1}`)    // initial value from LocalStorage will be 47, because "PropA" initialized already
                 .onClick(() => this.storLink1 += 1 ) 
        
            // Child @Component receives access to CompA' LocalStorage instance automatically.
            Child() 
       }
   }
}