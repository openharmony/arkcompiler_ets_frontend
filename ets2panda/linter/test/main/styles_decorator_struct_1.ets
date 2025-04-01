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

@Component
struct MyCard1 {
  @Styles
  cardStyle1() {
    .backgroundColor('#ffffff')
    .borderRadius(8)
  }

  build() {
    Column() {
      Text('Card')
    }
    .cardStyle1()
  }
}

@Component
struct MyButton {
  @BuilderParam
  @Require
  content: () => void;

  @Styles
  NormalStyles() {
    .backgroundColor(Color.Red)
  }

  @Styles
  PressedStyles() {
    .backgroundColor(Color.Green)
  }

  build() {
    Button() {
      this.content
    }
    .stateStyles({
      normal: this.NormalStyles(),
      pressed: this.PressedStyles()
    })
  }
}