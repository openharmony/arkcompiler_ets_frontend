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

@Reusable
@Component
struct MyListItem {
  @State item: MyImage = new MyImage('', '')

  aboutToReuse(params) {
    this.item = params.itemLogger.info(TAG, 'aboutToReuse-,item=' + this.item.toString())
  }

  build() {
    Row({ space: 10 }) {
      Image(this.item.image_path)
        .width(50)
        .height(50)
        .borderRadius(5)
        .autoResize(false)
        .syncLoad(true)
      Blank()
      Text(this.item.image_path)
        .fontColor(Color.Black)
        .fontSize(15)
    }
  }
}
