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

import java.util.List;

class Main {
	// Java language allows to omit return/parameter types for lambda expression.
	// These types are then inferred by the compiler.
	// This test covers all kinds of types that can be inferred by compiler

	class C {}
	enum E {}
	interface IPrimitiveTypes { void M(int i, boolean b, char c); } // Void, primitive types
	interface IClassTypes { IPrimitiveTypes M(C c, String s, E e); } // Class, Interface, Enum
	interface IArrays { int[] M(String[] sArray, IPrimitiveTypes[][] iArray, E[] eArray[]); } // Arrays
	interface IParametrizedTypes { List M(List<Integer> list, List<IPrimitiveTypes[]> listOfArrays, List<List<String>> listOfLists[]); } // Parametrized type, Raw type
	interface IWildcards { List<?> M(List<? extends Number> listExtends, List<? super Integer> listSuper); } // Wildcards
	interface IGeneric<T> { T M(List<T> list); } // Generic interface (parametrized types, type variables, wildcards, etc.)

	static class OuterClass<T> {
		class InnerClass {
			void M(T t) {
				IGeneric<T> l = (list) -> list.get(0); // Generic functional interface parametrized with type variable
			}
		}
	}
	interface IInnerOuter {
		int M(OuterClass<List<String>>.InnerClass inner); // Nested type (with parametrized type)
	}

	void Test() {
		IPrimitiveTypes l1 = (i, b, c) -> { }; // Void, primitive types
		IClassTypes l2 = (c, s, e) -> l1; // Class, Interface, Enum
		IArrays l3 = (sArray, iArray, eArray) -> new int[5]; // Arrays
		IParametrizedTypes l4 = (list, listOfArrays, ListOfLists) -> list;  // Parametrized type, Raw type
		IWildcards l5 = (listExtends, listSuper) -> listExtends;  // Wildcards

		// Generic functional interface
		IGeneric<Number> l6 = (list) -> list.get(0); // parametrized with explicit type
		IGeneric<?> l7 = (list) -> list.get(0); // parametrized with wildcard
		IGeneric<? extends Number> l8 = (list) -> list.get(0); // parametrized with wildcard with bound
		IGeneric<? super Number> l9 = (list) -> list.get(0); // parametrized with wildcard with bound

		IInnerOuter l10 = (inner) -> 0; // Nested type (with parametrized type)
	}
}