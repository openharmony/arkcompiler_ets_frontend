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

class MethodReferencesExamples {

    interface Function0<T> {
        T apply();
    }
    interface Function1<T, R> {
        R apply(T t);
    }
    interface Function2<T, U, R> {
        R apply(T t, U u);
    }
    interface Consumer<T> {
        void apply(T t);
    }
    interface BiConsumer<T, U> {
        void apply(T t, U u);
    }

    public <T> T factory(Function0<T> f) {
        return f.apply();
    }
    public <T, R> R factory(Function1<T, R> f, T t) {
        return f.apply(t);
    }
    public <T, U, R> R factory(Function2<T, U, R> f, T t, U u) {
        return f.apply(t, u);
    }

    static class Person {
        public Person() {}
        public Person(int age) {}
        public Person(int age, String name) {}

        public void sleep(int hours) {}
    }

    public static <T> T mergeThings(T a, T b, Function2<T, T, T> merger) {
        return merger.apply(a, b);
    }

    public static String appendStrings(String a, String b) {
        return a + b;
    }

    public String appendStrings2(String a, String b) {
        return a + b;
    }

    static class A {
        static class B {
            public void foo() {}
            public static void bar(String s) {}
        }
    }

    class Generic<T> {
        public void bar(T t) {}
    }

    public static void classMethodReferences() {
        MethodReferencesExamples myApp = new MethodReferencesExamples();

        // Reference to static method | ContainingClass::staticMethodName
        System.out.println(MethodReferencesExamples.
                mergeThings("Hello ", "World!", MethodReferencesExamples::appendStrings));

        // Reference to an instance method of a particular object | containingObject::instanceMethodName
        System.out.println(MethodReferencesExamples.
                mergeThings("Hello ", "World!", myApp::appendStrings2));

        // Reference to an instance method of an arbitrary object of a particular type | ContainingType::methodName
        System.out.println(MethodReferencesExamples.
                mergeThings("Hello ", "World!", String::concat));

        // Reference to a constructor | ClassName::new
        Person person = myApp.factory(Person::new);
        Person person2 = myApp.factory(Person::new, 25);
        Person person3 = myApp.factory(Person::new, 40, "Peter");

        // Reference with qualified type name
        Consumer<A.B> cons1 = A.B::foo;
        Consumer<String> cons2 = A.B::bar;

        // Reference with parametrized type name
        BiConsumer<Generic, Integer> generic = Generic<Integer>::bar;

        // Reference with primary expressions
        Function0<Integer> getLength = "sleeping"::length;
        int length = getLength.apply();

        Person[] persons = new Person[5];
        Consumer<Integer> sleep = persons[2]::sleep;
        sleep.apply(length);
    }

    // Arrays
    interface ArrayFactory<T> {
        T[] createArray(int size);
    }
    interface ArrayFactory2<T> {
        T[][] createArray(int size);
    }
    interface ArrayFactory3<T> {
        T[][][] createArray(int size);
    }

    public static void arrayMethodReferences() {
        MethodReferencesExamples myApp = new MethodReferencesExamples();

        Function1<Integer[], Integer[]> arrayClone = Integer[]::clone;
        arrayClone.apply(new Integer[]{1, 2, 3});

        int[] intArray = new int[]{1, 2, 3, 4, 5};
        Function0<int[]> arrayClone2 = intArray::clone;
        intArray = arrayClone2.apply();

        intArray = myApp.factory(intArray::clone);
        intArray = myApp.factory(int[]::clone, intArray);
    }

    public static void arrayCreationReferences() {
        ArrayFactory<Integer> arrayFactory1 = Integer[]::new;
        Integer[] newArray = arrayFactory1.createArray(5);

        ArrayFactory2<String> arrayFactory2 = String[][]::new;
        String[][] newArray2 = arrayFactory2.createArray(10);
        
        ArrayFactory3<Double> arrayFactory3 = Double[][][]::new;
        Double[][][] newArray3 = arrayFactory3.createArray(15);

        java.util.Arrays.stream(new Object[5]).toArray(String[]::new);
    }

    // Varargs
    interface IVarargs {
        int m(String s, int[] i);
    }

    interface IVarargs2 {
        int m(String s, int... i);
    }

    interface IVarargs3 {
        int m(String s, int[]... i);
    }

    static class VarArgs {
        int m1(String s, int[] i) { return 5; }
        int m2(String s, int... i) { return 5; }
        int m3(String s, int[]... i) { return 5; }
    }

    public static void methodReferencesWithVarargs() {
        VarArgs obj = new VarArgs();

        IVarargs i1m1 = obj::m1;
        IVarargs2 i2m1 = obj::m1;
        IVarargs3 i3m1 = obj::m1; // Illegal

        IVarargs i1m2 = obj::m2;
        IVarargs2 i2m2 = obj::m2;
        IVarargs3 i3m2 = obj::m2; // Illegal

        IVarargs i1m3 = obj::m3;
        IVarargs2 i2m3 = obj::m3;
        IVarargs3 i3m3 = obj::m3;
    }

    // Inner/outer classes
    interface FooMethod {
        int foo(int x);
    }
    interface InnerFactory {
        Outer.Inner create();
    }
    static class OuterBase {
        public int foo(int x) { return x + 5; }
    }
    public static class Outer extends OuterBase {
        public int foo(int x) { return x - 5; }

        public void bar() {
            FooMethod thisFoo = this::foo;
            FooMethod superFoo = super::foo;

            // Local inner class
            class LocalInner {
                void foo() {
                    FooMethod outerThisFoo = Outer.this::foo;
                    FooMethod outerSuperFoo = Outer.super::foo;
                }
            }
        }

        // Inner class
        class Inner {
            void foo() {
                FooMethod outerThisFoo = Outer.this::foo;
                FooMethod outerSuperFoo = Outer.super::foo;
            }

            InnerFactory innerContext() {
                return Inner::new; // Creation reference from Inner context
            }
        }

        public void outerContext() {
            InnerFactory factory = Inner::new; // Creation reference from Outer context
            Inner inner = factory.create();
        }
    }

    // Exceptions and error handling
    interface TryFunction0<T> {
        T apply() throws MyException;
    }
    interface TryFunction1<T, R> {
        R apply(T t) throws MyException;
    }
    class MyException extends Exception { }
    static class Exceptions {
        public Exceptions() throws MyException { }
        public String getName() throws MyException { return "George"; }
    }

    public static void methodReferencesWithExceptions() {

        try {
            TryFunction0<Exceptions> createExceptions = Exceptions::new;
            Exceptions exceptions = createExceptions.apply();

            TryFunction1<Exceptions, String> getNameFun = Exceptions::getName;
            String name = getNameFun.apply(exceptions);
        } catch(MyException ex) { }
    }
}
