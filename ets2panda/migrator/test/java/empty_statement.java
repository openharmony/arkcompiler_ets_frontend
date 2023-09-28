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

class empty_statement {
	int a;
	public void Test() {

	a = 10; ; ;
	;

        int i = 0;
        while (i < 2) ;
        do ; while (i > 3);
        for ( ; i < 10; ++i) ;
        for (int s = 1; s < 2; ++s) ;
        for (char c : "string".toCharArray()) ;
        if (i != 0) ;
        if (i == 0) {
            ++i;
        }
        else ;

    	}

	public void Run() {
		;
	}
}
