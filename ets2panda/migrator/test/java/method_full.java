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

package com.ohos.migrator.tests.java;

abstract class method_full {
   void foo() {
   }

   void foo_void(boolean b) {
      return;
   }

   int foo_int(double b, char c, int i) {
      return 1;
   }

   boolean foo_bool(double d, char c, int ... i) {
      return true;
   }

   private int foo_private(double d) { return 2;}

   public final double foo_final(double d) { return 1.;}

   protected static boolean foo_final(int i) { return false; }

   protected abstract int foo_abstract();

   private native int foo_native();
}
