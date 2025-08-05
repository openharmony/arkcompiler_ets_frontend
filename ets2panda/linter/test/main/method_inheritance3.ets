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
 
class A<T>{
  getData(a:T):T{
    return a;
  }
}

class B extends A<number>{
  getData(a: number): number {  // no error
    return 123;
  }
}

enum E{
  E1,
  E2
}

interface I {
  fun(e:E):void
}

class C implements I {
  fun(e:E):void{  // no error

  }
}

Class UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void;
  onWindowStageCreate(windowStage: window.WindowStage): void;
}

class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void { // no error

  }

  onWindowStageCreate(windowStage: window.WindowStage): void {  // no error
    try {
      windowStage.loadContent('pages/Index', (err: BusinessError<void> | null): void => {
        if (err && err.code) {
          return;
        }
      });
    } catch (e) {
    }
  }
}