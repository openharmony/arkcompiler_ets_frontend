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

class class_instance_creation {
    class_instance_creation(int i) {}
    class_instance_creation() {}
    class_instance_creation(String s, double d) {}

    public void foo() { }

    static class_instance_creation inst1 = new class_instance_creation();
    static class_instance_creation inst2 = new class_instance_creation(3);
    static class_instance_creation inst3 = new class_instance_creation("ss", 7.8);
    static class_instance_creation inst4 = new class_instance_creation(3) {
                                                   private int f;
                                                   { f = 3; }
                                                   public void foo() { f = 2; }
                                               };

    class inner_class {
        inner_class(int i) {}
    }

    inner_class inner_inst1 = new inner_class(1);
    inner_class inner_inst2 = inst1.new inner_class(2);
    inner_class inner_inst3 = inst4.new inner_class(3) {
                            private String s;
                            public void bar() { s = "bar"; }
                            { bar(); }
                        };
}
