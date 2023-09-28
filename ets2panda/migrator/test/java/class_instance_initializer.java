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

class A {
    int a = 1;
    {
        a = 2;
    }

    int b = 3;
    {
        b = 4;
    }

    public A() {
        // Inits are inserted here.
        a = 10;
        b = 20;
    }

    public A(int p) {
        // Inits are NOT inserted here.
        this();
        a = 30;
        b = 40;
    }

    public A(String s) {
        // Inits are inserted here.
        a = 50;
        b = 60;
    }
}

class B extends A {
    int c = 11;
    {
        c += 22;
    }

    int d = 33;
    {
        d -= 44;
    }

    public B() {
        // Inits are inserted here.
        c = 100;
        d = 200;
    }

    public B(int p) {
        // Inits are NOT inserted here.
        this();
        c = 300;
        d = 400;
    }

    public B(String s) {
        super(0);
        // Inits are inserted here (after super() call).
        c = 500;
        d = 600;
    }
}

// instance initializer without ctors
class C {
    String foo;

    { foo = "bar"; }
}
