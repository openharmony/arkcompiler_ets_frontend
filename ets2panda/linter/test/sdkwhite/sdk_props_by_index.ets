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

// if in real env, remvoe './sdk/'
import { AccessibilityExtensionAbility } from './sdk/@kit.AccessibilityKit';

class EntryAbility extends AccessibilityExtensionAbility {
  onConnect(): void {
    let axContext = this.context;
    let accessibilityElement = axContext.getFocusElement();
    accessibilityElement.then((data) => {
      data.attributeValue<'accessibilityFocused'>('accessibilityFocused'); // error
    });
  }

  noErrorCase(): void {
    let localAccessibilityElement = customFoo();
    localAccessibilityElement.then((data) => {
      data.attributeValue<'accessibilityFocused'>('accessibilityFocused'); // ok
    });

    let axContext = this.context;
    let notAccessibilityElement = axContext.getFocusElementNotAccessibilityElement();
    notAccessibilityElement.then((data) => {
      data.attributeValue<'accessibilityFocused'>('accessibilityFocused'); // ok
    });
  }
}
interface AccessibilityElement {
  attributeValue<T extends keyof ElementAttributeValues>(
    attributeName: T,
    callback: AsyncCallback<ElementAttributeValues[T]>
  ): void;
  attributeValue<T extends keyof ElementAttributeValues>(attributeName: T): Promise<ElementAttributeValues[T]>;
}

async function customFoo(): Promise<AccessibilityElement> {
  return (await {}) as AccessibilityElement;
}
