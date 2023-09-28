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

class MyException extends Exception {
    MyException() { }
    MyException(String s) { super(s); }
}

class AnotherException extends Exception {
}

class SuperClass {
    private String s;
    public SuperClass(String s) throws MyException { 
	    if(s == null) throw new MyException();
	    this.s = s;
    }
    void foo() { System.out.println(s); }
}

class SubClass1 extends SuperClass {

    public SubClass1(String s) throws AnotherException, MyException {
    	super(s);
    	if(s == null ) throw new AnotherException();
    }

    void foo()	throws UnsupportedOperationException {
    	throw new UnsupportedOperationException();
    }

    public void run() throws UnsupportedOperationException {
            foo();
    }

    public void toto() throws MyException { throw new MyException(); }
}


class SubClass2 extends SubClass1 {

    public SubClass2(String s) throws AnotherException, MyException, UnsupportedOperationException {
    	    super(s);
	    if( s == "!" ) throw new UnsupportedOperationException(); 
    }
    
    public void foo() throws UnsupportedOperationException { super.foo(); }
    public void bar() throws UnsupportedOperationException, AnotherException { super.foo(); throw new AnotherException(); }
    public void toto() throws MyException { super.toto(); }  
}
        

class Test  {

    // throws
    public static void test1(String s)  throws MyException, AnotherException {
	SubClass1 sc1 = new SubClass1(s);
	sc1.foo();
    }

    // throws
    public static void test2(String s) throws AnotherException {
	    try {
		   SubClass1 sc1 = new SubClass1(s);
	    }
	    catch( MyException e ) {}
    }

    // no throws - all exceptions are catched
    public static void test3(String s) {
    	try {
		SubClass1 sc1 = new SubClass1(s);
	}
	catch( MyException | AnotherException e) {}
    }

    // no throws - only runtime exceptions 
    public static void test4(String s) {
	try {
		SubClass2 sc2 = new SubClass2(s);	
	}
	catch( MyException | AnotherException e) {}
    }

    // no throws - only runtime exceptions
    public static void test5(String s) {
	try {
        	SubClass2 sc2 = new SubClass2(s);
		sc2.foo();
        }
        catch( MyException | AnotherException e) {}
    }

    // throws
    public static void test6(String s) throws AnotherException {
        try {
                SubClass2 sc2 = new SubClass2(s);
                sc2.bar();
        }
        catch( MyException  e) {}

    }


    // test for constructor with static initializer
    static class E1 extends Exception {}
    static class E2 extends Exception {}
    static class E3 extends Exception {}

    static abstract class Ta {
            public abstract void m() throws E1, E2;
    }

    interface Tb {
            void m() throws E2, E3;
    }

    
    // intersect throws clauses
    static abstract class Tc extends Ta implements Tb {
        {
            try {
                m();
            }
            catch ( E2 e2 ) {
            }
        }
    }


    // STS constructor must have throws clause 
    static abstract class Td extends Ta {
     {
            try {
                m();
            }
            catch ( E2 e2 ) {
            }
        }
    
     public Td() throws E1 {
     }

    }


    interface FunctionalInterface { void foo(); }
    abstract class AbstractException extends Error implements FunctionalInterface {}

    final AbstractException notInitialized = (AbstractException)( (FunctionalInterface)( () -> { throw notInitialized; } ) );
}

