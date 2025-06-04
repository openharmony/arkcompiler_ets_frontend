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

@Entry
@Component
struct TestStateStyle {
  @BuilderParam
  @Require
  content: () => void;

  build() {
    Button() {
      this.content
    }
    .stateStyles({
      normal: {
        .backgroundColor("#00ffff")
        .borderWidth(8);
      },
      pressed: {
        .backgroundColor(Color.Red)
        .backgroundImagePosition({
          x: 0,
          y: 0
        })
        .backgroundColor("#ffff00");
      }
    })
  }
}