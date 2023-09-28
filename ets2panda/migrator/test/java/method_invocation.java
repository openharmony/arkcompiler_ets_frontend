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

class SuperClass {
    void foo() { System.out.println("Hi"); }
}

class SubClass1 extends SuperClass {
    void foo() { throw new UnsupportedOperationException(); }

    Runnable tweak = new Runnable() {
        public void run() {
            SubClass1.super.foo(); // Gets the 'println' behavior
        }
    };
}

interface SuperInterface {
    default void foo() { System.out.println("Hi"); }
}

class SubClass2 implements SuperInterface {
    public void foo() { throw new UnsupportedOperationException(); }

    void tweak() {
        SuperInterface.super.foo(); // Gets the 'println' behavior
    }
}

class SubClass3 implements SuperInterface {
    public void foo() { throw new UnsupportedOperationException(); }

    Runnable tweak = new Runnable() {
        public void run() {
            SubClass3.SuperInterface.super.foo(); // Illegal
        }
    };
}

class Doubler {
    static int two() { return two(1); }

    private static int two(int i) { return 2 * i; }
}
class Test extends Doubler {
    static long two(long j) { return j+j; }

    public static void main(String[] args) {
        System.out.println(two(3));
        System.out.println(Doubler.two(3)); // Compile-time error
    }
}

class ColoredPoint {
    int x, y;
    byte color;

    void setColor(byte color) { this.color = color; }
}
class Test2 {
    public static void main(String[] args) {
        ColoredPoint cp = new ColoredPoint();
        byte color = 37;
        cp.setColor(color);
        cp.setColor(37); // Compile-time error
    }
}

class Point { int x, y; }
class ColoredPoint2 extends Point { int color; }
class Test3 {
    static void test(ColoredPoint p, Point q) {
        System.out.println("(ColoredPoint, Point)");
    }
    static void test(Point q, ColoredPoint p) {
        System.out.println("(Point, ColoredPoint)");
    }
    public static void main(String[] args) {
        ColoredPoint2 cp = new ColoredPoint2();
        test(cp, cp); // Compile-time error
    }
}
