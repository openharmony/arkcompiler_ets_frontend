/*
* Copyright (c) 2022-2023 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at 
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable low or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import prompt from '@ohos.prompt';

@Styles function btnGlobalPressedStyle() {
  .backgroundColor(Color.Pink)
  .width(180)
  .height(50)
}

@Styles function btnGlobalNormalStyle() {
  .backgroundColor(Color.Blue)
  .width(180)
  .height(50)
}


@Entry @Component struct ToastTest {

  @State text: string = "";
  @State area: string = "";

  build() {
    Column({space: 10}) {

      Button("Toast")
        .stateStyles({
          normal: btnGlobalNormalStyle,
          pressed: btnGlobalPressedStyle
        })
        .onClick(() => {
          prompt.showToast({
            message: "test"
          })
        })
    }
    .width('100%')
    .height('100%')
    .padding(10)
  }
}
