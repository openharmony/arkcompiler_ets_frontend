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

interface Fun<T,R> { R apply(T arg); }

class C {
    Integer size() { return 0; }

    Integer size(Object arg) { return 1; }

    Integer size(C arg) { return 2; }

    static class H {
        Integer size() {return 3;}
    }

    H h = new H();

    private interface Func<C, R> {
        R apply(C c);
    }

    void test1() {
        Func<C, Integer> f1 = (C c) -> c.size();
        System.out.print(f1.apply(this));
    }

    void test2() {
        Func<H, Integer> f1 = (H h) -> h.size();
        System.out.print(f1.apply(h));
    }
}

class Main {
    public static void main(String args[]) {
        C c = new C();
        c.test1();
        c.test2();
    }
}