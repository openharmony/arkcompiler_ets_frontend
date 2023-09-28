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

public class throw_statement {
    private final int i = 0x7fff;

    public class Panic extends RuntimeException {}
    
    public int divide_test(int j) throws Exception {
	if( j == 0 ) throw new Exception();
	return i / j ; 	
    }
    
    public int divide_test(long l) throws Panic {
    	if( l > i ) throw new Panic();
	return  (int) (i / l) ;
    }

}
