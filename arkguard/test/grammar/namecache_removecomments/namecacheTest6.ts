/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


class MyDataSource {
  data: string[] = ["a", "b", "c", "d", "e"];
  public totalCount(): number {
      return this.data.length;
  }
  public getData(index: number): string {
      return this.data[index];
  }
}

// A simplified version of ArkUI `LazyForEach` in SDK
class LazyForEach {
    create(id: string, component: any, source: any, itemGenFunction: any, itemIdFunc: any): void {};
}

let lazyforeach: LazyForEach = new LazyForEach();

class MyComponent {
  constructor(params, __localStorage) {
      this.source = new MyDataSource();
      this.setInitiallyProvidedValue(params);
  }
  setInitiallyProvidedValue(params) {
      if (params.source !== undefined) {
          this.source = params.source;
      }
  }
  observeComponentCreation2() {};
  private source: MyDataSource;
  initialRender() {
      this.observeComponentCreation2();
      {
          const __lazyForEachItemGenFunction = (_item, index?: number) => {
              const item = _item;
              {
                  const observedDeepRender = () => {
                  };
                  observedDeepRender();
              }
          };
          const __lazyForEachItemIdFunc = (item: string, index?: number) => index?.toString() + item;
          lazyforeach.create("1", this, this.source, __lazyForEachItemGenFunction, __lazyForEachItemIdFunc);
      }
  }
}