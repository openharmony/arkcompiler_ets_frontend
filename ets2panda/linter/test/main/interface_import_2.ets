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

import { Row, Slider, Entry, Component, State, Column, Button, Text, TextAttribute, ColumnAttribute, AnimatableExtend, $$, ImageFit } from '@ohos.arkui.components';

@Entry
@Component
struct Test {

  @State col: number = 0;

  build() {
    Column() {
      Button('按钮')
        .backgroundColor('#ffffff')
      Circle() {
        
      }
      .stateStyles({

      })

      MyComponent() {

      }

      Text("Test")
    }.width("100%")
  }
}

enum Color {
  Green
}

function Circle() {

}

@Component
struct MyComponent {
  @State count: number = 0;
  build() {
    Row() {
      Slider(){}
    }
  }
}

function cardStyle(this: TextAttribute): TextAttribute
{
  this.backgroundColor1('#ffffff');
  return this;
}

@AnimatableExtend
function animatableWidth(this: ColumnAttribute, width: number) {
  this.width(width)
  return this;
}

@Component
struct Myomponent {
  @State value: number = 0;
  build() {
    Row() {
      Slider({
        value: $$(this.value)
      })
    }
  }
}