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

import { CommonMethod, Color, Entry, Component, BuilderParam, Require, Button } from '@kit.ArkUI';

function NormalStyles(instance: CommonMethod): void {
    instance.backgroundColor(Color.Blue);
}

@Entry
@Component
struct MyButton {
  @BuilderParam
  @Require
  content: () => void;

  PressedStyles = (instance: CommonMethod): void => {
    instance.backgroundColor(Color.Green);
  };

  build() {
    Button() {
      this.content
    }
    .stateStyles({
      selected: (instance: CommonMethod): void => {
          instance.backgroundColor(menuItem.disable ? null : $r('sys.color.ohos_id_color_clicl_effect'));
      },
      pressed: this.PressedStyles,
      normal: NormalStyles
    })
  }
}
