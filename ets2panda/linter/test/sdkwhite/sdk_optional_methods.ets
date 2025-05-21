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

import { webview } from '@kit.ArkWeb';
import { AbilityLifecycleCallback, UIAbility } from '@kit.AbilityKit';

class OptionalMethod implements webview.NativeMediaPlayerBridge {
  updateRect(x: number, y: number, width: number, height: number): void {
    throw new Error('Method not implemented.');
  }

  play(): void {
    throw new Error('Method not implemented.');
  }

  pause(): void {
    throw new Error('Method not implemented.');
  }

  seek(targetTime: number): void {
    throw new Error('Method not implemented.');
  }

  setVolume(volume: number): void {
    throw new Error('Method not implemented.');
  }

  setMuted(muted: boolean): void {
    throw new Error('Method not implemented.');
  }

  setPlaybackRate(playbackRate: number): void {
    throw new Error('Method not implemented.');
  }

  release(): void {
    throw new Error('Method not implemented.');
  }

  enterFullscreen(): void {
    throw new Error('Method not implemented.');
  }

  exitFullscreen(): void {
    throw new Error('Method not implemented.');
  }

  resumePlayer?(): void { // Error
    throw new Error('Method not implemented.');
  }

  suspendPlayer?(type: webview.SuspendType): void { // Error
    throw new Error('Method not implemented.');
  }
}

class MyAbilityLifecycleCallback extends AbilityLifecycleCallback {
  // 用例1: 重写为必选方法 预期报错 用例结果--Error 未识别
  onWillNewWant(ability: UIAbility) {
    console.log('AbilityLifecycleCallback onWillNewWant.');
  }

  // 用例2: 重写为可选方法 预期报错 用例结果--Pass
  onAbilityWillCreate?(ability: UIAbility) {
    console.log('AbilityLifecycleCallback onAbilityWillCreate.');
  }

  // 用例3：使用必选属性重写父类方法 预期无报错 用例结果--Pass
  onAbilityWillForeground: (ability: UIAbility) => void =
    (ability: UIAbility) => {
      console.log('AbilityLifecycleCallback onAbilityWillForeground');
    }
  // 用例4：使用可选属性重写父类方法 预期无报错 用例结果--Pass
  onAbilityWillBackground?: (ability: UIAbility) => void =
    (ability: UIAbility) => {
      console.log('AbilityLifecycleCallback onAbilityWillBackground');
    }
}

// 用例5 类型断言 预期无报错 用例结果--Pass
const callback: AbilityLifecycleCallback = {
  onAbilityWillForeground: (ability: UIAbility): void => {
      console.log('AbilityLifecycleCallback onAbilityWillForeground');
    }
} as AbilityLifecycleCallback;

// 用例6 泛型类拓展
class GenericHandler<T extends UIAbility> extends AbilityLifecycleCallback {
  // 预期报错 用例结果--Error 未识别
  onAbilityWillCreate(ability: T): void { /*...*/ }
  // 预期无报错 用例结果--Pass
  onAbilityWillForeground: (ability: T) => void =
    (ability: T) => {
      console.log('AbilityLifecycleCallback onAbilityWillForeground');
    }
}

// 接口不能继承类；不能使用交叉类型扩展；不能声明合并


