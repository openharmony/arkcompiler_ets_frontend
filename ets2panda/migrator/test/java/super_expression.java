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

interface I { int x = 0; }

class T1 implements I { int x = 1; }

class T2 extends T1 { int x = 2; }

class T3 extends T2 {
    int x = 3;

    void test() {
        System.out.println("x=\t\t" + x);
        System.out.println("super.x=\t\t" + super.x);
        System.out.println("((T2)this).x=\t" + ((T2)this).x);
        System.out.println("((T1)this).x=\t" + ((T1)this).x);
        System.out.println("((I)this).x=\t" + ((I)this).x);
    }
}
class Test {
    public static void main(String[] args) {
        new T3().test();
    }
}