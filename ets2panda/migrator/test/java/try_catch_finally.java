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

class BlewIt extends Exception {
    BlewIt() { }
    BlewIt(String s) { super(s); }
}

public class try_catch_finally {
    public try_catch_finally() throws Exception { }

    public try_catch_finally(int i) throws Exception { this(); }

    static void blowUp() throws BlewIt { }

    private static void foo() throws BlewIt {
        try {
            blowUp();
        }
        finally {
            System.out.println("In finally");
        }
    }

    public static void main(String[] args) {
        try {
            blowUp();
            try_catch_finally t = new try_catch_finally();
        }
        catch (NullPointerException n) { 
            System.out.println("Caught NullPointerException");
        }
        catch (BlewIt | IllegalArgumentException b) {
            System.out.println("Caught BlewIt or IllegalArgumentException");
        }
        catch (RuntimeException r) {
            System.out.println("Caught RuntimeException");
        }
        catch (Exception e) {
            System.out.println("Caught Exception");
        }
        finally {
            System.out.println("In finally");
        }
    }
}
