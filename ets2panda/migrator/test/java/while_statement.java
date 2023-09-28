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

class while_statement {
    public static void Test() {
	final boolean Flag = true;
        int i = 0;
        int j = 0;
        
        while (Flag) break;

        while (Flag) {
            break;
        }

        while ( i< 10 ) {
            i++;
            if (i == 2) continue;
            if (i == 5) break;
        }

        outerLoop:
        while (i < 5) {
            
            innerLoop:
            while ( j < 5 ) {
                if (j == 2) continue innerLoop;
                if (i * j == 20) break outerLoop;
            }
        }
    }
}
