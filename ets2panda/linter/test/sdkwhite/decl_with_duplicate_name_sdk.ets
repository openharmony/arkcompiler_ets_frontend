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
'use static'

import { TextStyle } from './sdk/declarations/styled_string'
import { HyperlinkAttribute, HyperlinkInterface } from './sdk/declarations/hyperlink'

@Entry
@Component
struct Index {
  fontStyleAttr1: TextStyle = new TextStyle({fontColor: Color.Blue}); // Error(2)
  fontStyleAttr2: TextStyle; // Error

  @State styleList: Array<TextStyle> = new Array(); // Error
  aboutToAppear() {
    for (let i = 15; i < 50; i++)
      this.styleList.push(new TextStyle({})); // Error
  }

  build() {
    List() {
      ForEach(this.styleList, (item: TextStyle) => {  // Error
        ListItem() {
          Text("Hello World")
            .fontSize(item.fontSize)
        }
      })
    }
  }
}

class TextStyleDemo2 extends TextStyle { // Error
  constructor() {
    super();
  }
}

let hyperlinkAttr1: HyperlinkAttribute = HyperlinkInterface;
let hyperlinkAttr2: HyperlinkAttribute = HyperlinkInterface.color('');
class HyperlinkTest {
  prop1: HyperlinkAttribute = HyperlinkInterface;
  prop2: HyperlinkAttribute = HyperlinkInterface.color('');
}
let hyperlinkAttr3: HyperlinkAttribute;
hyperlinkAttr3 = HyperlinkInterface;
function func(x = HyperlinkInterface) {

}
