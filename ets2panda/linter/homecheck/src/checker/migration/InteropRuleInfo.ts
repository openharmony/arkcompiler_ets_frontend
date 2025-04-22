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

export const INTEROP_STATIC_OBJECT_BUILDIN_METHODS: InteropRuleInfo = {
    ruleId: 'interop-static-Ojbect-builtin-methods',
    severity: 1,
    description: ''
};

export const INTEROP_STATIC_REFLECT_BUILDIN_METHODS: InteropRuleInfo = {
    ruleId: 'interop-static-Reflect-builtin-methods',
    severity: 1,
    description: ''
};

export const INTEROP_DYNAMIC_OBJECT_BUILDIN_METHODS: InteropRuleInfo = {
    ruleId: 'interop-dynamic-Ojbect-builtin-methods',
    severity: 1,
    description: ''
};

export const INTEROP_DYNAMIC_REFLECT_BUILDIN_METHODS: InteropRuleInfo = {
    ruleId: 'interop-dynamic-Reflect-builtin-methods',
    severity: 1,
    description: ''
};

export function findInteropRule(methodLang: Language, objLang: Language, isReflect: boolean): InteropRuleInfo | undefined {
    if (methodLang === Language.ARKTS1_2 && objLang === Language.ARKTS1_1) {
        return isReflect ? INTEROP_STATIC_REFLECT_BUILDIN_METHODS : INTEROP_STATIC_OBJECT_BUILDIN_METHODS;
    }
    if (methodLang === Language.ARKTS1_1 && objLang === Language.ARKTS1_2) {
        return isReflect ? INTEROP_DYNAMIC_REFLECT_BUILDIN_METHODS : INTEROP_DYNAMIC_OBJECT_BUILDIN_METHODS;
    }
    if (methodLang === Language.TYPESCRIPT && objLang === Language.ARKTS1_2) {
        return isReflect ? INTEROP_STATIC_REFLECT_BUILDIN_METHODS : INTEROP_STATIC_OBJECT_BUILDIN_METHODS;
    }
    return undefined;
}