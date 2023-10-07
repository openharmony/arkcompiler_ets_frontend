/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

package com.ohos.migrator.test.java;

public class TestBoolean {
    public static void func() {
        Boolean v1 = Boolean.TRUE;
        Boolean v2 = Boolean.FALSE;
        Class<Boolean> v3 = Boolean.TYPE;
        boolean v4 = Boolean.TRUE.booleanValue();
        int v5 = Boolean.compare(Boolean.TRUE, Boolean.FALSE);
        int v6 = Boolean.TRUE.compareTo(Boolean.TRUE);
        boolean v7 = Boolean.TRUE.equals(Boolean.TRUE);
        boolean v8 = Boolean.getBoolean("false");
        int v9 = Boolean.hashCode(false);
        int v10 = Boolean.TRUE.hashCode();
        boolean v11 = Boolean.logicalAnd(false, true);
        boolean v12 = Boolean.logicalOr(false, true);
        boolean v13 = Boolean.logicalXor(false, true);
        boolean v14 = Boolean.parseBoolean("true");
        String v15 = Boolean.toString(true);
        String v16 = Boolean.TRUE.toString();
        boolean v17 = Boolean.valueOf(true);
        boolean v18 = Boolean.valueOf("");
    }
}
