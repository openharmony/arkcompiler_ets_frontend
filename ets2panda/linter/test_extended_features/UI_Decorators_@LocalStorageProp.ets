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

function getRandomColor() : string {
    return "#ff" + rndHexStr(255) + rndHexStr(255) + rndHexStr(255);
}

function rndHexStr(max : number) : string {
    return Math.floor(Math.random() * max).toString(16);
}

// Create and initialize AppStorage singleton
// property name 'color'
AppStorage.setOrCreate("color", getRandomColor());

// Create and initialize LocalStorage object
// property name 'color'
let storage = new LocalStorage({ color: getRandomColor() });

console.log(`Created and initialized LocalStorage and AppStorage: read-back 
  LocalStorage 'color': ${storage.get<string>('color')}
  AppStorage 'color': ${AppStorage.get<string>('color')}
  Values are different? ${storage.get<string>('color') != AppStorage.get<string>('color') ? 'yes' : 'no (likely a framework bug)'} .`);


@Entry(storage)
@Component
struct Parent {

// @StorageProp and @LocalStorageProp have one-way sync from AppStorage/from LocalStorage, @Watch catches local changes
@StorageLink("color")      @Watch("onStateChange") storLinkColor      : string = getRandomColor();
@StorageProp("color")      @Watch("onStateChange") storPropColor      : string = getRandomColor();  
@LocalStorageLink("color") @Watch("onStateChange") localStorLinkColor : string = getRandomColor();
@LocalStorageProp("color") @Watch("onStateChange") localStorPropColor : string = getRandomColor();  

// set by onStateChange to the name / the value of the last changed variable.
// see @Watch onStateChange cb function
@State lastChangedVariableName  : string = "n/a";
@State lastChangedVariableValue : string = "n/a";

onStateChange(watchedVarName : string) {
  // copy var name and its value to @State variables for display
  this.lastChangedVariableName = watchedVarName;
  this.lastChangedVariableValue = this[watchedVarName];
}

build() {
    Column() {
      Text("AppStorage.link: 'storLinkColor'")
        .width(200).height(60).fontSize(12)
        .backgroundColor(this.storLinkColor)
        .onClick(() => this.storLinkColor = getRandomColor() )

      Text("AppStorage.prop: 'storPropColor'")
        .width(200).height(60).fontSize(12)
        .backgroundColor(this.storPropColor)
        .onClick(() => this.storPropColor = getRandomColor() )

      Divider()
       .width(200).height(10)

      Text("LocalStorage.link: 'localStorLinkColor'")
        .width(200).height(60).fontSize(12)
        .backgroundColor(this.localStorLinkColor)
        .onClick(() => this.localStorLinkColor = getRandomColor() )

      Text("LocalStorage.prop: 'localStorPropColor'")
        .width(200).height(60).fontSize(12)
        .backgroundColor(this.localStorPropColor)
        .onClick(() => this.localStorPropColor = getRandomColor() )

      Divider()
       .width(200).height(10)

      Text(`@Watch Last @Component var changed: ${this.lastChangedVariableName}`)
        .width(200).height(60).fontSize(12)
        .backgroundColor(this.lastChangedVariableValue)
    }
  }
}