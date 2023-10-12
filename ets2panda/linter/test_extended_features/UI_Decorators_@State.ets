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

@Entry @Component struct ComponentTest {

  @State date: string = "Time:" + new Date().getTime(); // Data changes will trigger the execution of the build method

  build() {
    Column({space: 10}) {

      Text(`Parent component【${this.date}】`) // Display time
        .fontSize(20)
        .backgroundColor(Color.Pink)

      Item() // subcomponent
      Item() // subcomponent

      Button('update time')
        .onClick(() => {
          this.date = "Time:" + new Date().getTime(); // Click the button and the date changes, which will trigger the execution of the build method
        })
    }
    .width('100%')
    .height('100%')
    .padding(10)
  }
}

// Custom subcomponent
@Component struct Item {

  @State time: string = "Time:" + new Date().getTime();

  build() {
    Text(`Subcomponent(${this.time})`)
      .fontSize(20)
      .backgroundColor(Color.Grey)
      .onClick(() => {
        this.time = "Time:" + new Date().getTime(); // Click to update the time and execute the build method
      })
  }
}
