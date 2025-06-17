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

import { UIAbility } from '@kit.AbilityKit';
import { MyAbility } from 'X';

class MyAbilityStage extends AbilityStage {
  onCreate() {
    let abilityLifecycleCallback: AbilityLifecycleCallback = {
      onAbilityCreate(ability：UIAbility) {
      let myAbility:MyAbility = ability as MyAbility;
      myAbility.foo()
    }
  }
    let applicationContext = appMgr.getApplicationContext();
    try {
      // 2.通过applicationContext注册监听应用内生命周期
      lifecycleId = applicationContext.on('abilityLifecycle', abilityLifecycleCallback); // Error
    } catch (paramError) {
      console.error(`error: ${(paramError as BusinessError).code}, ${(paramError as BusinessError).message}`);
    }
  }
}
