/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { Language } from 'arkanalyzer/lib/core/model/ArkFile';

export class InteropRuleInfo {
    ruleId: string;
    severity: number;
    description: string;
}

// 1.2 import 1.1
// 1.1 Object => ArkTS 1.2 对象
export const D2S_DYNAMIC_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-d2s-dynamic-object-on-static-instance',
    severity: 1,
    description: "ArkTS 1.1 Object's built-in methods work on ArkTS 1.2 objects",
};

// 1.2 import 1.1
// 1.1 Reflect => ArkTS 1.2 对象
export const D2S_DYNAMIC_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-d2s-dynamic-reflect-on-static-instance',
    severity: 1,
    description: "ArkTS 1.1 Reflect's built-in methods work on ArkTS 1.2 objects",
};

// 1.2 import 1.1
// 1.2 Object => ArkTS 1.1 对象
export const D2S_STATIC_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-d2s-static-object-on-dynamic-instance',
    severity: 1,
    description: "ArkTS 1.2 Object's built-in methods work on ArkTS 1.1 objects",
};

// 1.2 import 1.1
// 1.2 Reflect => ArkTS 1.1 对象
export const D2S_STATIC_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-d2s-static-reflect-on-dynamic-instance',
    severity: 1,
    description: "ArkTS 1.2 Reflect's built-in methods work on ArkTS 1.1 objects",
};

// 1.1 import 1.2
// 1.1 Object => ArkTS 1.2 对象
export const S2D_DYNAMIC_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-s2d-dynamic-object-on-static-instance',
    severity: 1,
    description: "ArkTS 1.1 Object's built-in methods work on ArkTS 1.2 objects",
};

// 1.1 import 1.2
// 1.1 Reflect => ArkTS 1.2 对象
export const S2D_DYNAMIC_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-s2d-dynamic-reflect-on-static-instance',
    severity: 1,
    description: "ArkTS 1.1 Reflect's built-in methods work on ArkTS 1.2 objects",
};

// 1.1 import 1.2
// 1.2 Object => 1.1 对象
export const S2D_STATIC_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-s2d-static-object-on-dynamic-instance',
    severity: 1,
    description: "ArkTS 1.2 Object's built-in methods work on ArkTS 1.1 objects",
};

// 1.1 import 1.2
// 1.2 Reflect => 1.1 对象
export const S2D_STATIC_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-s2d-static-reflect-on-dynamic-instance',
    severity: 1,
    description: "ArkTS 1.2 Reflect's built-in methods work on ArkTS 1.1 objects",
};

export const TS_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-ts2s-ts-object-on-static-instance',
    severity: 1,
    description: "TypeScript Object's built-in methods work on ArkTS objects",
};

export const TS_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-ts2s-ts-reflect-on-static-instance',
    severity: 1,
    description: "TypeScript Reflect's built-in methods work on ArkTS objects",
};

export const JS_OBJECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-js2s-js-object-on-static-instance',
    severity: 1,
    description: "JavaScript Object's built-in methods work on ArkTS objects",
};

export const JS_REFLECT: InteropRuleInfo = {
    ruleId: 'arkts-interop-js2s-js-reflect-on-static-instance',
    severity: 1,
    description: "JavaScript Reflect's built-in methods work on ArkTS objects",
};

export function findInteropRule(
    methodLang: Language,
    typeDefLang: Language,
    problemStmtLang: Language,
    isReflect: boolean
): InteropRuleInfo | undefined {
    if (methodLang === Language.ARKTS1_2 && typeDefLang === Language.ARKTS1_1) {
        if (problemStmtLang === Language.ARKTS1_1) {
            // 包含 object API 的 1.2 函数被导出到 1.1 文件使用
            return isReflect ? S2D_STATIC_REFLECT : S2D_STATIC_OBJECT;
        } else {
            return isReflect ? D2S_STATIC_REFLECT : D2S_STATIC_OBJECT;
        }
    }
    if (methodLang === Language.ARKTS1_1 && typeDefLang === Language.ARKTS1_2) {
        if (problemStmtLang === Language.ARKTS1_2) {
            // 包含 object API 的 1.1 函数被导出到 1.2 文件使用
            return isReflect ? D2S_DYNAMIC_REFLECT : D2S_DYNAMIC_OBJECT;
        } else {
            return isReflect ? S2D_DYNAMIC_REFLECT: S2D_DYNAMIC_OBJECT ;
        }
    }
    if (methodLang === Language.TYPESCRIPT && typeDefLang === Language.ARKTS1_2) {
        return isReflect ? TS_REFLECT : TS_OBJECT;
    }
    if (methodLang === Language.JAVASCRIPT && typeDefLang === Language.ARKTS1_2) {
        return isReflect ? JS_REFLECT : JS_OBJECT;
    }
    return undefined;
}