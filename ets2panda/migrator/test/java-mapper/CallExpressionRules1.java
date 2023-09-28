/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

import java.util.ArrayList;
import java.util.List;

class CallExpressiontRules1 {
    public static void Test() {
        List<Integer> lst = new ArrayList<Integer>();
        lst.add(1);
        lst.add(2);

        for (int i = 0; i < lst.size(); i++) {
            System.out.print(lst.get(i));
        }

        System.out.println(lst.get(0));

        Number d[] = lst.toArray(new Number[0]);

        System.out.println(d);
    }
}