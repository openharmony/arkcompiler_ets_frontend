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

import java.util.List;
import java.util.ArrayList;

public class unresolved_types {
    public static void foo(Yoo b) {
        int = 1;
    }

    public static void baz(List<Yoo> l) {
        int i = 1;
    }

    public static unresolved_types()
    {
        List<Yoo> l = new ArrayList<>();
        l.add(null);


    }
}
