..  Copyright (c) 2021-2024 Huawei Device Co., Ltd.
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

Recipes
=======

.. _R001:

|CB_R| #1: Objects with property names that are not identifiers are not supported
---------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support Objects with name properties that are numbers or
strings. Use classes to access data by property names. Use arrays to access data
by numeric indices.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

   var x = {"name": 1, 2: 3}

   console.log(x["name"])
   console.log(x[2])

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class X {
        public name: number
    }
    let x = {name: 1}
    console.log(x.name)

    let y = [1, 2, 3]
    console.log(y[2])

    // If you still need a container to store keys of different types,
    // use Map<Object, some_type>:
    let z = new Map<Object, number>()
    z.set("name", 1)
    z.set(2, 2)
    console.log(z.get("name"))
    console.log(z.get(2))

|CB_SEE|
~~~~~~~~

* :ref:`R002`
* :ref:`R052`
* :ref:`R059`
* :ref:`R060`
* :ref:`R066`
* :ref:`R105`
* :ref:`R109`

.. _R002:

|CB_R| #2: ``Symbol()`` API is not supported
--------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``Symbol()`` API.

|CB_BAD|
~~~~~~~~

|TS| has ``Symbol()`` API, which can be used among other things to generate
unique property names at runtime:

.. code-block:: typescript

    const sym = Symbol()
    let o = {
       [sym]: "value"
    }

|CB_OK|
~~~~~~~

|LANG| does not support ``Symbol()`` API because its most popular use cases
make no sense in the statically typed environment. In particular, the object
layout is defined at compile time and cannot be changed at runtime.

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R052`
* :ref:`R059`
* :ref:`R060`
* :ref:`R066`
* :ref:`R105`
* :ref:`R109`

.. _R003:

|CB_R| #3: Private '#' identifiers are not supported
----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not private identifiers started with ``#`` symbol, use ``private`` keyword instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class C {
      foo = 1
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class C {
      private foo = 1
    }


.. _R004:

|CB_R| #4: Use unique names for types, namespaces, etc.
-------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Names for types, namespaces and so on must be unique and distinct from other
names, e.g., variable names.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let X: string
    type X = number[] // Type alias with the same name as the variable

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let X: string
    type T = number[] // X is not allowed here to avoid name collisions

.. _R005:

|CB_R| #5: Use ``let`` instead of ``var``
-----------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``var``, always use ``let`` instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function f(shouldInitialize: boolean) {
        if (shouldInitialize) {
           var x = 10
        }
        return x
    }

    console.log(f(true))  // 10
    console.log(f(false)) // undefined

    let upper_let = 0
    {
        var scoped_var = 0
        let scoped_let = 0
        upper_let = 5
    }
    scoped_var = 5 // Visible
    scoped_let = 5 // Compile-time error

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function f(shouldInitialize: boolean): Object {
        let x: Object = new Object();
        if (shouldInitialize) {
            x = 10
        }
        return x
    }

   console.log(f(true));  // 10
   console.log(f(false)); // {}

    let upper_let = 0
    let scoped_var = 0
    {
        let scoped_let = 0
        upper_let = 5
    }
    scoped_var = 5
    scoped_let = 5 // Compile-time error

.. _R008:

|CB_R| #8: Use explicit types instead of ``any``, ``undefined``, ``unknown``
----------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``any``, ``undefined``, and ``unknown`` types.
Specify types explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    var x
    console.log(x) // undefined

    var y: any
    console.log(y) // undefined

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // All variables should have their types specified explicitly:
    let x: Object = {}
    console.log(x) // {}

|CB_SEE|
~~~~~~~~

.. _R009:

|CB_R| #9: You can extend your |TS| code with more numeric types
----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports different numeric types on top of just ``number``.

|CB_BAD|
~~~~~~~~

|TS| supports ``number`` as the only numeric type:

.. code-block:: typescript

    let x: number = 1

|CB_OK|
~~~~~~~

|LANG| supports several numeric types:

+-----------+----------+-------------------------------------------------------------+
| Type      | Size     | Range                                                       |
+===========+==========+=============================================================+
|``byte``   | 8 bits   |``[-128 .. 127]``                                            |
+-----------+----------+-------------------------------------------------------------+
|``short``  | 16 bits  |``[-32,768 .. 32,767]``                                      |
+-----------+----------+-------------------------------------------------------------+
|``int``    | 32 bits  |``[-2,147,483,648 .. 2,147,483,647]``                        |
+-----------+----------+-------------------------------------------------------------+
|``long``   | 64 bits  |``[-9,223,372,036,854,775,808 .. 9,223,372,036,854,775,807]``|
+-----------+----------+-------------------------------------------------------------+
|``ubyte``  | 8 bits   |``[0 .. 255]``                                               |
+-----------+----------+-------------------------------------------------------------+
|``ushort`` | 16 bits  |``[0 .. 65,535]``                                            |
+-----------+----------+-------------------------------------------------------------+
|``uint``   | 32 bits  |``[0 .. 4,294,967,295]``                                     |
+-----------+----------+-------------------------------------------------------------+
|``ulong``  | 64 bits  |``[0 .. 18,446,744,073,709,551,615]``                        |
+-----------+----------+-------------------------------------------------------------+
|``float``  | 32 bits  |``3.4E +/- 38 (7 digits)``                                   |
+-----------+----------+-------------------------------------------------------------+
|``double`` | 64 bits  |``1.7E +/- 308 (15 digits)``                                 |
+-----------+----------+-------------------------------------------------------------+

Additionally, |LANG| supports the following types:

* Character type ``char`` (the range of values is the same as ``ushort``)
* Boolean type ``boolean`` (values: ``true``, ``false``)

.. code-block:: typescript

    let x: int = 1
    let y: boolean = true
    let z: char = 'a'

.. _R010:

|CB_R| #10: Use ``long`` instead of ``bigint``
----------------------------------------------

|CB_RULE|
~~~~~~~~~

Use ``long`` to work with 64-bit integers.

|CB_BAD|
~~~~~~~~

|TS| supports ``bigint`` data type, but this feature is available only since
ES2020 and requires ``n`` suffix for numeric literals:

.. code-block:: typescript

    let a: bigint = 1n

|CB_OK|
~~~~~~~

|LANG| provides ``long`` data type to work with 64-bit
integers, ``n`` suffix is not supported:

.. code-block:: typescript

    let x: long = 1

.. _R012:

|CB_R| #12: Use ``T[]`` instead of ``Array<T>`` to declare arrays
-----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

In |TS|, arrays can be declared as either ``Array<T>`` or ``T[]``. Currently,
|LANG| supports only the second syntax for array declaration.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // These are equivalent in TypeScript:
    let y: Array<string> = ["1", "2", "3"]

|CB_OK|
~~~~~~~

.. code-block:: typescript

   let x: string[] = ["1", "2", "3"];
   let y: string[] = ["1", "2", "3"]; // Array<string> is not supported currently

.. _R014:

|CB_R| #14: Use ``class`` instead of a type with call signature
---------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support call signatures in object types. Use classes instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    type DescribableFunction = {
        description: string
        (someArg: number): string // call signature
    }

    function doSomething(fn: DescribableFunction): void {
        console.log(fn.description + " returned " + fn(6))
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class DescribableFunction {
        description: string;
        public invoke(someArg: number): string {
            return someArg.toString()
        }
        constructor() {
            this.description = "desc"
        }
    }

    function doSomething(fn: DescribableFunction): void {
        console.log(fn.description + " returned " + fn.invoke(6))
    }

    doSomething(new DescribableFunction());

|CB_SEE|
~~~~~~~~

* :ref:`R015`

.. _R015:

|CB_R| #15: Use ``class`` instead of a type with constructor signature
----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support constructor signatures in object types. Use classes
instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class SomeObject {}

    type SomeConstructor = {
        new (s: string): SomeObject
    }

    function fn(ctor: SomeConstructor) {
        return new ctor("hello");
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class SomeObject {
        public f: string
        constructor (s: string) {
            this.f = s
        }
    }

    function fn(s: string): SomeObject {
        return new SomeObject(s)
    }

|CB_SEE|
~~~~~~~~

* :ref:`R014`

.. _R016:

|CB_R| #16: Only one static block is supported
----------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not allow to have sevaral static block for class initialization, combine static blocks statements to the one static block.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class C {
        static s: string

        static {
            C.s = "aa"
        }
        static {
            C.s = C.s + "bb"
        }
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript


    class C {
        static s: string

        static {
            C.s = "aa"
            C.s = C.s + "bb"
        }
    }


.. _R017:

|CB_R| #17: Indexed signatures are not supported
------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not allow indexed signatures, use arrays instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // Interface with an indexed signature:
    interface StringArray {
        [index: number]: string
    }

    const myArray: StringArray = getStringArray()
    const secondItem = myArray[1]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class X {
        public f: string[]
    }

    let myArray: X = new X()
    const secondItem = myArray.f[1]

.. _R019:

|CB_R| #19: Use inheritance instead of intersection types
---------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support intersection types. You can use inheritance
as a work-around.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    interface Identity {
        id: number
        name: string
    }

    interface Contact {
        email: string
        phone: string
    }

    type Employee = Identity & Contact

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface Identity {
        id: number
        name: string
    }

    interface Contact {
        email: string
        phone: string
    }

    interface Employee extends Identity,  Contact {}

.. _R021:

|CB_R| #21: Returning ``this`` type is not supported
----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the returning ``this`` type. Use explicit type instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    interface ListItem {
        getHead(): this
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface ListItem {
        getHead(): ListItem
    }

.. _R023:

|CB_R| #22: Conditional types are not supported
----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support conditional type aliases. Introduce a new type with constraints explicitly or rewrite logic with use of ``Object``.
``infer`` keyword is not supported.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    type X<T> = T extends number ? T : never

    type Y<T> = T extends Array<infer Item> ? Item : never

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // Provide explicit contraints within type alias
    type X1<T extends number> = T

    // Rewrite with Object. Less type control, need more type checks for safety
    type X2<T> = Object

    // Item has to be used as a generic parameter and need to be properly instantiated
    type YI<Item, T extends Array<Item>> = Item


|CB_R| #23: Type queries are not supported
------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support specifying types via ``typeof``.
All types must be specified explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    var a = {x: 10, y: 20}
    var b: typeof a

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class A {
        public x: number = 10
        public y: number = 20
    }

    let a: A
    let b: A

.. _R025:

|CB_R| #25: Declaring fields in ``constructor`` is not supported
----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support declaring class fields in the ``constructor``.
You must declare them inside the ``class`` declaration instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Person {
        constructor(
            protected ssn: string,
            private firstName: string,
            private lastName: string
        ) {
            this.ssn = ssn
            this.firstName = firstName
            this.lastName = lastName
        }

        getFullName(): string {
            return this.firstName + " " + this.lastName
        }
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

   class Person {
        protected ssn: string
        private firstName: string
        private lastName: string

        constructor(ssn: string, firstName: string, lastName: string) {
            this.ssn = ssn
            this.firstName = firstName
            this.lastName = lastName
        }

        getFullName(): string {
            return this.firstName + " " + this.lastName
        }
    }

.. _R027:

|CB_R| #27: Construct signatures not supported in interfaces
------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support construct signatures. Use methods instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    interface I {
        new (s: string): I
    }

    function fn(i: I) {
        return new i("hello");
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface I {
        create(s: string): I
    }

    function fn(i: I) {
        return i.create("hello")
    }

|CB_SEE|
~~~~~~~~

* :ref:`R015`

.. _R028:

|CB_R| #28: Indexed access types are not supported
--------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support indexed access types. Use the type name instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    type Point = {x: number, y: number}
    type N = Point["x"] // is equal to number

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Point {x: number = 0; y: number = 0}
    type N = number

.. _R029:

|CB_R| #29: Indexed access is not supported for fields
------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support indexed access for class fields. Use dot notation instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Point {x: number = 0; y: number = 0}
    let p: Point = {x: 1, y: 2}
    let x = p["x"]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Point {x: number = 0; y: number = 0}
    let p: Point = {x: 1, y: 2}
    let x = p.x

.. _R030:

|CB_R| #30: Structural identity is not supported
------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support structural identity, i.e., the compiler
cannot compare two types' public APIs and decide whether such types are
identical. Use other mechanisms (inheritance, interfaces or type aliases)
instead.

In |TS|, types ``X`` and ``Y`` are equal (interchangeble), while in |LANG|
they are not.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    interface X {
        f(): string
    }

    interface Y { // Y is equal to X
        f(): string
    }

|CB_OK|
~~~~~~~

|LANG| does not support structural identity. In the static environment the
compiler checks if two classes or interfaces are equal, but there is no way
to compare unrelated (by inheritance or interface) classes that are
structurally equivalent.

.. code-block:: typescript

    interface X {
        f(): string
    }

    type Y = X // Y is equal to X

|CB_SEE|
~~~~~~~~

* :ref:`R031`
* :ref:`R032`
* :ref:`R035`


.. _R031:

|CB_R| #31: Structural typing is not supported for subtyping / supertyping
--------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not check structural equivalence for type inference, i.e.,
the compiler cannot compare two types' public APIs and decide whether such types
are identical.
Use other mechanisms (inheritance or interfaces) instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class X {
        public foo: number

        constructor() {
            this.foo = 0
        }
    }

    class Y {
        public foo: number

        constructor() {
            this.foo = 0
        }
    }

    let x = new X()
    let y = new Y()

    console.log("Assign X to Y")
    y = x

    console.log("Assign Y to X")
    x = y


|CB_OK|
~~~~~~~

.. code-block:: typescript

    class X {
        public foo: number

        constructor() {
            this.foo = 0
        }
    }

    // Y is derived from X, which explicitly set subtype / supertype relations:
    class Y extends X {
        constructor() {
            super()
        }
    }

    let x = new X()
    let y = new Y()

    console.log("Assign X to Y")
    y = x // ok, X is the super class of X

    // Cannot assign Y to X
    //x = y - compile-time error


|CB_SEE|
~~~~~~~~

* :ref:`R030`
* :ref:`R032`
* :ref:`R035`

.. _R032:

|CB_R| #32: Structural typing is not supported for assignability checks
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not check structural equivalence when checking if types
are assignable to each other, i.e., the compiler cannot compare two types'
public APIs and decide whether such types are identical. Use other mechanisms
(inheritance or interfaces) instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class X {
        public foo: number

        constructor() {
           this.foo = 0
        }
    }

    class Y {
        public foo: number
        constructor() {
            this.foo = 0
        }
    }

    let x = new X()
    let y = new Y()

    console.log("Assign X to Y")
    y = x

    console.log("Assign Y to X")
    x = y

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface Z {
       foo: number
    }

    // X implements interface Z, which makes relation between X and Y explicit.
    class X implements Z {
        public foo: number

        constructor() {
           this.foo = 0
        }
    }

    // Y implements interface Z, which makes relation between X and Y explicit.
    class Y implements Z {
        public foo: number

        constructor() {
           this.foo = 0
        }
    }

    let x: Z = new X()
    let y: Z = new Y()

    console.log("Assign X to Y")
    y = x // ok, both are of the same type

    console.log("Assign Y to X")
    x = y // ok, both are of the same type

|CB_SEE|
~~~~~~~~

* :ref:`R030`
* :ref:`R031`
* :ref:`R035`

.. _R034:

|CB_R| #34: Generic functions must be called with explicit type specialization
------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support inference of type parameters in case of calls
to generic functions. If a function is declared generic, all calls must specify
type parameters explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function choose<T>(x: T, y: T): T {
        return Math.random() < 0.5 ? x : y
    }

    let x = choose(10, 20) // Ok
    let y = choose("10", 20) // Compile-time error

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function choose<T>(x: T, y: T): T {
        return Math.random() < 0.5 ? x : y
    }

    let x = choose<number>(10, 20) // Ok
    let y = choose<number>("10", 20) // Compile-time error

.. _R035:

|CB_R| #35: Structural typing is not supported for type inference
-----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support structural typing, i.e., the compiler cannot
compare two types' public APIs and decide whether such types are identical.
Use inheritance and interfaces to specify the relation between the types
explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class X  {
        public foo: number
        private s: string

        constructor (f: number) {
            this.foo = f
            this.s = ""
        }

        public say(): void {
           console.log("X = ", this.foo)
        }
    }

    class Y {
        public foo: number

        constructor (f: number) {
            this.foo = f
        }
        public say(): void {
            console.log("Y = ", this.foo)
        }
    }

    function bar(z: X): void {
        z.say()
    }

    // X and Y are equivalent because their public API is equivalent.
    // Thus the second call is allowed:
    bar(new X(1));
    bar(new Y(2));

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface Z {
       say(): void
    }

    class X implements Z {
        public foo: number
        private s: string

        constructor (f: number) {
            this.foo = f
            this.s = ""
        }
        public say(): void {
            console.log("X = ", this.foo)
        }
    }

    class Y implements Z {
        public foo: number

        constructor (f: number) {
            this.foo = f
        }
        public say(): void {
            console.log("Y = ", this.foo)
        }
    }

    function bar(z: Z): void {
        z.say()
    }

    // X and Y implement the same interface Z, thus both calls are allowed:
    bar(new X(1))
    bar(new Y(2))

|CB_SEE|
~~~~~~~~

* :ref:`R030`
* :ref:`R031`
* :ref:`R032`

.. _R037:

|CB_R| #37: RegExp literals are not supported
---------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support RegExp literals. Use library call with string
literals instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

   let regex: RegExp = /bc*d/

|CB_OK|
~~~~~~~

.. code-block:: typescript

   let regex: RegExp = new RegExp("/bc*d/")

.. _R038:

|CB_R| #38: Object literal must correspond to explicitly declared class or interface
------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports the usage of object literals if the compiler can infer
to what classes or interfaces such literals correspond to. 
Otherwise, a compile-time error occurs.  

The class or interface can be specified as a type annotation for a variable.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

   let x = {f: 1}

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class O {
       f: number
    }

    let x: O = {f: 1} // OK
    let y = {f: 1} // Compile-time error, cannot infer object literal type
    let z: Object = {f: 2} // Compile-time error, class 'Object' does not have field 'f'

|CB_SEE|
~~~~~~~~

* :ref:`R040`
* :ref:`R043`

.. _R040:

|CB_R| #40: Object literals cannot be used as type declarations
---------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the usage of object literals to declare
types in place. Declare classes and interfaces explicitly instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let o: {x: number, y: number} = {
        x: 2,
        y: 3
    }

    type T = G<{x: number, y: number}>

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class O {
        x: number
        y: number
    }

    let o: O = {x: 2, y: 3}

    type T = G<O>

|CB_SEE|
~~~~~~~~

* :ref:`R038`
* :ref:`R043`

.. _R043:

|CB_R| #43: Untyped array literals are not supported
----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the usage of untyped array literals.  The type of an
array element must be inferred from the context. Use the type ``Object`` to
define mixed types array.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let x = [1, 2]
    let y = [1, "aa"]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let x: Object[] = [new Int(1), new Int(2)]

    // Implicit boxing of primitive int to object Int
    let x1: Object[] = [1, 2]

    let y: Object[] = [1, "aa"]

|CB_SEE|
~~~~~~~~

* :ref:`R038`
* :ref:`R040`

.. _R044:

|CB_R| #44: Template literals are not supported
-----------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support template literals. You may use a ``+``
concatenation as a work-around.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    const a = 5
    const b = 10
    console.log(`Fifteen is ${a + b}`)

|CB_OK|
~~~~~~~

.. code-block:: typescript

    const a = 5
    const b = 10

    // (a + b) is converted to Int and then toString() method is called:
    console.log("Fifteen is " + (a + b))

.. _R045:

|CB_R| #45: Lambdas require explicit type annotation for parameters
-------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| requires the types of lambda parameters 
to be explicitly specified.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let f = (s) => { // type any is assumed
            console.log(s)
        }

|CB_OK|
~~~~~~~

Explicit types for lambda parameters are mandatory.

.. code-block:: typescript

    let f =
        (s: string) => {
            console.log(s)
        }

|CB_SEE|
~~~~~~~~

* :ref:`R047`

.. _R046:

|CB_R| #46: Use arrow functions instead of function expressions
-------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support function expressions, use arrow functions instead
to be explicitly specified.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let f = function (s: string) { 
            console.log(s)
        }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let f = (s: string) => {
            console.log(s)
        }

.. _R047:

|CB_R| #47: Return type must be specified for lambdas explicitly
----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

An explicit return type is mandatory for a lambda expression.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let f = (s: string) => { // return type is implicit
            return s.toLowerCase()
        }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let f = (s: string): string => { // return type is explicit
            return s.toLowerCase()
        }

|CB_SEE|
~~~~~~~~

* :ref:`R045`

.. _R049:

|CB_R| #49: Usage of arrow function with type assertions or generics
--------------------------------------------------------------------

|CB_BAD|
~~~~~~~~

A non-compliant syntax is used. Not a part of the common subset.

.. code-block:: typescript

    let generic_arrow_func =
        <T extends String> (x: T) => { return x }
    let type_asserted_function =
        <() => boolean> (() => {return true})

    generic_arrow_func(5) // Compile-time error
    generic_arrow_func("string")
    type_asserted_function()

|CB_OK|
~~~~~~~

Introduce a new function to replace an arrow function with generics.
Explicit types are mandatory, static typing replaces type assertions by design.

.. code-block:: typescript

    function generic_arrow_func<T extends String>(x: T): T {
        return x
    }

    let type_asserted_func: () => boolean =
        (): boolean => {return true}

    generic_arrow_func(5) // Compile-time error
    generic_arrow_func("string")

    type_asserted_func()

.. _R050:

|CB_R| #50: Class literals are not supported
--------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support class literals. A new named class type must be
introduced explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    const Rectangle = class {
        constructor(height: number, width: number) {
            this.heigth = height
            this.width = width
        }

        heigth
        width
    }

    const rectangle = new Rectangle(0.0, 0.0)

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Rectangle {
        constructor(height: number, width: number) {
            this.heigth = height
            this.width = width
        }

        heigth: number
        width: number
    }

    const rectangle = new Rectangle(0.0, 0.0)

.. _R051:

|CB_R| #51: Classes cannot be specified in ``implements`` clause
----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not allow to specify a class in implements clause. Only interfaces may be specified.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class C {
      foo() {}
    }
    
    class C1 implements C {
      foo() {}
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface C {
      foo()
    }
    
    class C1 implements C {
      foo() {}
    }


.. _R052:

|CB_R| #52: Attempt to access an undefined property is a compile-time error
---------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports accessing only those class properties that are either declared
in the class, or accessible via inheritance. Accessing any other properties is
prohibited and causes compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let person = {name: "Bob", isEmployee: true}

    let n = typ["name"]
    let e = typ["isEmployee"]
    let s = typ["office"] // undefined

|CB_OK|
~~~~~~~

Use proper types to check property existence during compilation.

.. code-block:: typescript

    class Person {
        constructor(name: string, isEmployee: boolean) {
            this.name = name
            this.isEmployee = isEmployee
        }

        name: string
        isEmployee: boolean
    }

    let person = new Person("Bob", true)
    let n = typ.name
    let e = typ.isEmployee
    let s = typ.office // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R059`
* :ref:`R060`
* :ref:`R066`
* :ref:`R105`
* :ref:`R109`

.. _R053:

|CB_R| #53: Only ``as T`` syntax is supported for type casts
------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports ``as`` keyword as the only syntax for type casts.
Incorrect cast causes a compile-time error or runtime ``ClassCastError``.
``<type>`` syntax for type casts is not supported.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Shape {}
    class Circle extends Shape {x: number = 5}
    class Square extends Shape {y: string = "a"}

    function createShape(): Shape {
        return new Circle()
    }

    let c1 = <Circle> createShape()

    let c2 = createShape() as Circle

    // No report is provided during compilation
    // nor during runtime if cast is wrong:
    let c3 = createShape() as Square
    console.log(c3.y) // undefined

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Shape {}
    class Circle extends Shape {x: number = 5}
    class Square extends Shape {y: string = "a"}

    function createShape(): Shape {
        return new Circle()
    }

    let c2 = createShape() as Circle

    // ClassCastError during runtime is thrown:
    let c3 = createShape() as Square

.. _R054:

|CB_R| #54: JSX expressions are not supported
---------------------------------------------

|CB_RULE|
~~~~~~~~~

Do not use JSX since no alternative is provided to rewrite it.

.. _R055:

|CB_R| #55: Unary operators ``+``, ``-`` and ``~`` work only on numbers
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| allows unary operators to work on numeric types only. A compile-time
error occurs if these operators are applied to a non-numeric type. Unlike in
|TS|, implicit casting of strings in this context is not supported and must
be done explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a = +5   // 5 as number
    let b = +"5" // 5 as number
    let c = -5   // -5 as number
    let d = -"5" // -5 as number
    let e = ~5   // -6 as number
    let f = ~"5" // -6 as number
    let g = +"string" // NaN as number

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = +5   // 5 as int
    let b = +"5" // Compile-time error
    let c = -5   // -5 as int
    let d = -"5" // Compile-time error
    let e = ~5   // -6 as int
    let f = ~"5" // Compile-time error
    let g = +"string" // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R056:

|CB_R| #56: Unary ``+`` cannot be used for casting to ``number``
----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support casting from any type to a numeric type
by using the unary ``+`` operator, which can be applied only to
numeric types.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function returnTen(): string {
        return "-10"
    }

    function returnString(): string {
        return "string"
    }

    let a = +returnTen()    // -10 as number
    let b = +returnString() // NaN

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function returnTen(): string {
        return "-10"
    }

    function returnString(): string {
        return "string"
    }

    let a = +returnTen()    // Compile-time error
    let b = +returnString() // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R057:

|CB_R| #57: ``!`` operator works only on values of the boolean type
-------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports using ``!`` operator only for values of the boolean type.
Explicit cast from some type to the boolean (or Boolean) is mandatory.
Implicit casts are prohibited and cause compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a = !true      // false
    let b = !"true"    // false
    let c = !"rnd_str" // false
    let d = !"false"   // false
    let e = !5         // false
    let f = !0         // true

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = !true      // false
    let b = !"true"    // Compile-time error
    let c = !"false"   // Compile-time error
    let d = !"rnd_str" // Compile-time error
    let e = !5         // Compile-time error
    let f = !0         // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R059:

|CB_R| #59: ``delete`` operator is not supported
------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| assumes that object layout is known at compile time and cannot be 
changed at runtime. Thus the operation of deleting a property makes no sense.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Point {
        x?: number = 0.0
        y?: number = 0.0
    }

    let p = new Point()
    delete p.y

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // To mimic the original semantics, you may declare a nullable type
    // and assign null to mark value absence:

    class Point {
        x: number | null
        y: number | null
    }

    let p = new Point()
    p.y = null

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R052`
* :ref:`R060`
* :ref:`R066`
* :ref:`R105`
* :ref:`R109`

.. _R060:

|CB_R| #60: ``typeof`` is allowed only in expression contexts
-------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports ``typeof`` operator only in the expression context.
Type notation with ``typeof`` is not supported.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let n1 = 42
    let s1 = "foo"
    console.log(typeof n1) // "number"
    console.log(typeof s1) // "string"
    let n2: typeof n1
    let s2: typeof s1

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let n1 = 42
    let s1 = "foo"
    console.log(typeof n1) // "number"
    console.log(typeof s1) // "string"
    let n2: number
    let s2: string

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R052`
* :ref:`R059`
* :ref:`R066`
* :ref:`R105`
* :ref:`R109`

.. _R061:

|CB_R| #61: Binary operators ``*``, ``/``, ``%``, ``-``, ``<<``, ``>>``, ``>>>``, ``&``, ``^`` and ``|`` work only on numeric types
-----------------------------------------------------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| allows applying binary operators ``*``, ``/``, ``%``, ``-``, ``<<``,
``>>``, ``>>>``, ``&``, ``^`` and ``|`` only to values of numeric types.
Implicit casts from other types to numeric types are prohibited and cause
compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a = (5 & 5)     // 5
    let b = (5.5 & 5.5) // 5, not 5.5
    let c = (5 | 5)     // 5
    let d = (5.5 | 5.5) // 5, not 5.5

    enum Direction {
        Up = -1,
        Down
    }
    let e = Direction.Up >> 1 // -1
    let f = Direction.Up >>> 1 // 2147483647

    let g = ("10" as any) << 1  // 20
    let h = ("str" as any) << 1 // 0

    let i = 10 * 5
    let j = 10 / 5
    let k = 10 % 5
    let l = 10 - 5

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = (5 & 5)     // 5
    let b = (5.5 & 5.5) // Compile-time error
    let c = (5 | 5)     // 5
    let d = (5.5 | 5.5) // Compile-time error

    enum Direction {
        Up, // TBD: explicit start value
        Down
    }

    let e = Direction.Up >> 1  // 0
    let f = Direction.Up >>> 1 // 0

    let i = 10 * 5
    let j = 10 / 5
    let k = 10 % 5
    let l = 10 - 5

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R062:

|CB_R| #62: Binary operators ``<<``, ``>>``, ``>>>``, ``&``, ``^`` and ``|`` work only on integral numeric types
----------------------------------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| expects an explicit cast to an integral type for logical binary
operations. Implicit casts are prohibited and cause compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let b = (5.5 & 5.5) // 5, not 5.5
    let d = (5.5 | 5.5) // 5, not 5.5

    let g = ("10" as any) << 1  // 20
    let h = ("str" as any) << 1 // 0

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let b = (5.5 & 5.5) // Compile-time error
    let d = (5.5 | 5.5) // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R063:

|CB_R| #63: Binary ``+`` operator supports implicit casts only for numbers and strings
--------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports implicit casts for ``+`` only for strings and numbers.
Elsewhere, any form of an explicit cast to string is required.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    enum E { E1, E2 }

    let a = 10 + 32   // 42
    let b = E.E1 + 10 // 10
    let c = 10 + "5"  // "105"

    let d = "5" + E.E2 // "51"
    let e = "Hello, " + "world!" // "Hello, world!"
    let f = "string" + true // "stringtrue"

    let g = (new Object()) + "string" // "[object Object]string"

|CB_OK|
~~~~~~~

.. code-block:: typescript

    enum E { E1, E2 }

    let a = 10 + 32   // 42
    let b = E.E1 + 10 // 10
    let c = 10 + "5"  // "105"

    let d = "5" + E.E2 // "51"
    let e = "Hello, " + "world!" // "Hello, world!"
    let f = "string" + true // "stringtrue"

    let g = (new Object()).toString() + "string"

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

.. _R064:

|CB_R| #64: Binary ``+`` operator requires explicit casts for non-numbers and non-strings
-----------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports implicit casts for ``+`` only for strings and numbers.
Elsewhere, any form of an explicit cast to string is required.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // "[object Object][object Object]"
    let o = ({x: 5} as any) + {y: 6}

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let o = (new Object()).toString() + new Int(5) // "5"

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R067`
* :ref:`R068`
* :ref:`R078`

|CB_R| #65: ``instanceof`` operator is partially supported
----------------------------------------------------------

|CB_RULE|
~~~~~~~~~

In |TS|, the left-hand side of an ``instanceof`` expression must be of type
``any``, an object type or a type parameter, otherwise the result is ``false``.
In |LANG|, the left-hand side expression may be of any reference type, otherwise
a compile-time error occurs. In addition, the left operand in |LANG| cannot be
a type.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class X {}

    let a = (new X()) instanceof Object // true
    let b = (new X()) instanceof X // true
    // left operand is a type:
    let c = X instanceof Object // true
    let d = X instanceof X // false

    // left operand is not of type any
    let e = (5.0 as Number) instanceof Number // false

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class X {}

    let a = (new X()) instanceof Object // true
    let b = (new X()) instanceof X // true
    // left operand is a type:
    let c = X instanceof Object // Compile-time error
    let d = X instanceof X // Compile-time error

    // left operand may be of any reference type, like number
    let e = (5.0 as Number) instanceof Number // true

.. _R066:

|CB_R| #66: ``in`` operator is not supported
--------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the ``in`` operator. However, this operator makes
little sense since the object layout is known at compile time and cannot
be modified at runtime. Use ``instanceof`` as a work-around if you still need
to check whether certain class members exist.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Person {
        name: string = ""
    }
    let p = new Person()

    let b = "name" in p // true

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Person {
        name: string = ""
    }
    let p = new Person()

    let b = p instanceof Person // true, and "name" is guaranteed to be present

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R052`
* :ref:`R059`
* :ref:`R060`
* :ref:`R105`
* :ref:`R109`

.. _R067:

|CB_R| #67: Operators ``&&`` and ``||`` work on values of the boolean type only
-------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports using ``&&`` and ``||`` operators only for the values of the
boolean type. Explicit cast from some type to the boolean (or Boolean) is
mandatory. Implicit casts are prohibited and cause compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a = true && false // false
    let b = 5 || 0        // 5
    let c = 5 && 0        // 0
    let d = "" && 5       // ""
    let e = "" || "abcd"  // "abcd"

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = true && false // false
    let b = 5 || 0        // Compile-time error
    let c = 5 && 0        // Compile-time error
    let d = "" && 5       // Compile-time error
    let e = "" || "abcd"  // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R068`
* :ref:`R078`

.. _R068:

|CB_R| #68: Using of ``&&`` and ``||`` on non-boolean types is not supported
----------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports the usage of ``&&`` and ``||`` operators only for the values
of the boolean type. Explicit cast from some type to the boolean (or Boolean)
is mandatory. Implicit casts are prohibited and cause compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a = true && false // false
    let b = 5 || 0        // 5
    let c = 5 && 0        // 0
    let d = "" && 5       // ""
    let e = "" || "abcd"  // "abcd"

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = true && false // false
    let b = 5 || 0        // Compile-time error
    let c = 5 && 0        // Compile-time error
    let d = "" && 5       // Compile-time error
    let e = "" || "abcd"  // Compile-time error

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R078`

.. _R069:

|CB_R| #69: Destructuring assignment is not supported
-----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support destructuring assignment. Other idioms (e.g.,
using a temporary variable, where applicable) can be used for replacement.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let [one, two] = [1, 2]
    [one, two] = [two, one]

    let head, tail
    [head, ...tail] = [1, 2, 3, 4]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let arr: number[] = [1, 2]
    let one = arr[0]
    let two = arr[1]

    let tmp = one
    one = two
    two = tmp

    let data: Number[] = [1,2,3,4]
    let head = data[0]
    let tail = new Number[data.length - 1]
    for (let i = 1; i < data.length; ++i) {
        tail[i-1] = data[i]
    }

.. _R071:

|CB_R| #71: The comma operator ``,`` is supported only in ``for`` loops
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports the comma operator ``,`` only in ``for`` loops. Otherwise,
it is useless as it makes the execution order harder to understand.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    for (let i = 0, j = 0; i < 10; ++i, j += 2) {
        console.log(i, j)
    }

    let x = 0
    x = (++x, x++) // 1

|CB_OK|
~~~~~~~

.. code-block:: typescript

    for (let i = 0, j = 0; i < 10; ++i, j += 2) {
        console.log(i, j)
    }

    // Use explicit execution order instead of the comma operator:
    let x = 0
    ++x
    x = x++

.. _R073:

|CB_R| #74: Destructuring variable declarations are not supported
-----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support destructuring variable declarations. This is a dynamic
feature relying on structural compatibility. In addition, names in destructuring
declarations must be equal to properties within destructured classes.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    class Point {
        x: number = 0.0
        y: number = 0.0
    }

    function returnZeroPoint(): Point {
        return new Point()
    }

    let {x, y} = returnZeroPoint()

|CB_OK|
~~~~~~~

.. code:: typescript

    class Point {
        x: number = 0.0
        y: number = 0.0
    }

    function returnZeroPoint(): Point {
        return new Point()
    }

    // Create an intermediate object and work with it field by field
    // without name restrictions:
    let zp = returnZeroPoint()
    let x = zp.x
    let y = zp.y

.. _R076:

|CB_R| #76: Inference of implied types is not supported
-------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support inference of implied types. Use explicit
type notation instead. Use ``Object[]`` if you need containers that hold
data of mixed types.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let [a, b, c] = [1, "hello", true]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = 1
    let b = "hello"
    let c = true

    let arr: Object[] = [1, "hello", true]
    let a1 = arr[0]
    let b1 = arr[1]
    let c1 = arr[2]

.. _R078:

|CB_R| #78: Implicit casts to the boolean are not supported in ``if``, ``do`` and ``while``
-------------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports only values of the boolean type in ``if``, ``do`` and ``while``
statements. Implicit casts from other types to the boolean are prohibited and
cause compile-time errors.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    if (true) {}
    do {} while (false)

    let a = new Boolean(true)
    if (a) {}
    do {break} while (a)
    while (a) {break}

    let b = 42
    if (b) {}
    do {break} while (b)
    while (b) {break}

    let c = "str"
    if (c) {}
    do {break} while (c)
    while (c) {break}

    let d = new Object()
    if (d) {}
    do {break} while (d)
    while (d) {break}

|CB_OK|
~~~~~~~

.. code-block:: typescript

    if (true) {}
    do {} while (false)

    let a = new Boolean(true)
    if (a) {}
    do {break} while (a)
    while (a) {break}

    let b = 42
    if (b != 0) {}
    do {break} while (b != 0)
    while (b != 0) {break}

    let c = "str"
    if (c.length != 0) {}
    do {break} while (c.length != 0)
    while (c.length != 0) {break}

    let d = new Object()
    if (d != null) {}
    do {break} while (d != null)
    while (d != null) {break}

|CB_SEE|
~~~~~~~~

* :ref:`R055`
* :ref:`R056`
* :ref:`R057`
* :ref:`R061`
* :ref:`R062`
* :ref:`R063`
* :ref:`R064`
* :ref:`R067`
* :ref:`R068`

.. _R079:

|CB_R| #79: Type annotation in catch clause is not supported
------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

In |TS| catch clause variable type annotation must be ``any`` or ``unknown`` if specified. 
As |LANG| does not support these types, a type annotation should be omitted.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    try { 
        // some code
    }
    catch (a: unknown) {}

|CB_OK|
~~~~~~~

.. code:: typescript

    try { 
        // some code
    }
    catch (a) {}

|CB_SEE|
~~~~~~~~

* :ref:`R087`

.. _R080:

|CB_R| #80: ``for .. in`` is not supported
------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the iteration over object contents by the
``for .. in`` loop. For objects, iteration over properties at runtime is
considered redundant because object layout is known at compile time and cannot
change at runtime. For arrays, you can iterate with the regular ``for`` loop.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let a: number[] = [1.0, 2.0, 3.0]
    for (let i in a) {
        console.log(a[i])
    }

|CB_OK|
~~~~~~~

.. code:: typescript

    let a: number[] = [1.0, 2.0, 3.0]
    for (let i = 0; i < a.length; ++i) {
        console.log(a[i])
    }

|CB_SEE|
~~~~~~~~

* :ref:`R081`
* :ref:`R082`

.. _R081:

|CB_R| #81: Iterable interfaces are not supported
-------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the ``Symbol`` API, ``Symbol.iterator`` and
eventually iterable interfaces. Use arrays and library-level containers to
iterate over data.

|CB_SEE|
~~~~~~~~

* :ref:`R002`
* :ref:`R080`
* :ref:`R082`

.. _R082:

|CB_R| ``for-of`` is supported only for arrays, strings, sets, maps and classes derived from them
-------------------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports the iteration over arrays, strings, sets, maps and classes
derived from them by the ``for .. of`` loop, but does not support the
iteration of objects content. All typed arrays from the standard
library (for example, ``Int32Array``) are also supported.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript
    class A {
        prop1: number;
        prop2: number;
    }
    let a = new A()
    for (let prop of a) {
        console.log(prop)
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let a = new Set<number>([1, 2, 3])
    for (let n of a) {
        console.log(n)
    }
|CB_SEE|
~~~~~~~~

* :ref:`R080`
* :ref:`R081`

.. _R083:

|CB_R| #83: Mapped type expression is not supported
---------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support mapped types. Use other language idioms and regular classes
to achieve the same behaviour.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

   type OptionsFlags<Type> = {
       [Property in keyof Type]: boolean;
   }

.. _R084:

|CB_R| #84: ``with`` statement is not supported
-----------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the ``with`` statement. Use other language idioms
(including fully qualified names of functions) to achieve the same behaviour.

.. _R085:

|CB_R| #85: Values computed at runtime are not supported in ``case`` statements
-------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports ``case`` statements that contain only compile-time values.
Use ``if`` statements as an alternative.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let x = 2
    let y = 3
    switch (x) {
        case 1:
            console.log(1)
            break
        case 2:
            console.log(2)
            break
        case y:
            console.log(y)
            break
        default:
            console.log("other")
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let x = 2
    switch (x) {
        case 1:
            console.log(1)
            break
        case 2:
            console.log(2)
            break
        case 3:
            console.log(3)
            break
        default:
            console.log("other")
    }

|CB_SEE|
~~~~~~~~

* :ref:`R112`

.. _R086:

|CB_R| #86: ``switch`` statements cannot accept values of arbitrary types
-------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports the values of the types ``char``, ``byte``, ``short``, ``int``,
``long``, ``Char``, ``Byte``, ``Short``, ``Int``, ``Long``, ``String`` or
``enum`` in ``switch`` statements. Use ``if`` statements in other cases.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Point {
        x: number = 0
        y: number = 0
    }

    let a = new Point()

    switch (a) {
        case null: break;
        default: console.log("not null")
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Point {
        x: number = 0
        y: number = 0
    }

    let a = new Point()

    if (a != null) {
        console.log("not null")
    }

.. _R087:

|CB_R| #87: ``throw`` statements cannot accept values of arbitrary types
------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| supports throwing only objects of the class ``Error`` or any
derived class. Throwing an arbitrary type (i.e., a ``number`` or ``string``)
is prohibited.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    throw 4
    throw ""
    throw new Error()

|CB_OK|
~~~~~~~

.. code-block:: typescript

    throw new Error()

.. _R088:

|CB_R| #88: Each overloaded function should have its body
---------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the |TS| style of overloading signatures with one
function body. Define each overloading function with its own body instead of
one body for a list of signatures.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    function add(x: number, y: number): number
    function add(x: string, y: string): string
    function add(x: any, y: any): any {
        return x + y
    }

    console.log(add(2, 3)) // returns 5
    console.log(add("hello", "world")) // returns "helloworld"

|CB_OK|
~~~~~~~

.. code:: typescript

    function add(x: number, y: number): number {
        return x + y
    }

    function add(x: string, y: string): string {
        return x + y
    }

    function main() {
        console.log(add(2, 3)) // returns 5
        console.log(add("hello", "world")) // returns "helloworld"
    }

|CB_SEE|
~~~~~~~~

* :ref:`R089`

.. _R089:

|CB_R| #89: Each overloaded function with optional parameters should have its body
----------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the |TS| style of overloading signatures with one
function body. Write a separate body for each overloaded signature instead of
an optional parameter like `value?` for a single body in |TS|.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    function foo(name: string): number
    function foo(name: string, value: string): Accessor
    function foo(name: any, value?: string): any {
        // one body here
    }

|CB_OK|
~~~~~~~

.. code:: typescript

    function foo(name: string): string {
        return name
    }

    function foo(name: string, value: string): Accessor {
        return new Accessor()
    }

|CB_SEE|
~~~~~~~~

* :ref:`R088`

.. _R090:

|CB_R| #90: Function must have explicit return type
---------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| requires all functions to have explicit return types. For corner cases,
use `Object` when it is difficult to determine the return type.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function f(x: number) {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    function g(x: number) {
        return f(x - 1)
    }

    function doOperation(x: number, y: number) {
        return x + y
    }

    console.log(f(10))
    console.log(doOperation(2, 3))

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function f(x: number): Object {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    function g(x: number): Object {
        return f(x - 1)
    }

    function doOperation(x: number, y: number): Object {
        let z = x + y
        return z
    }

    function main(): void {
        console.log(f(-10) as number) // returns -10
        console.log(doOperation(2, 3)) // returns 5
    }

|CB_R| #91: Destructuring parameter declarations are not supported
------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| requires that parameters must be passed directly to the function, and
local names must be assigned manually.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    function drawText({ text = "", location: [x, y] = [0, 0], bold = false }) {
        console.log(text)
        console.log(x)
        console.log(y)
        console.log(bold)
    }

    drawText({ text: "Hello, world!", location: [100, 50], bold: true })

|CB_OK|
~~~~~~~

.. code:: typescript

    function drawText(text: String, location: number[], bold: boolean) {
        let x = location[0]
        let y = location[1]
        console.log(text)
        console.log(x)
        console.log(y)
        console.log(bold)
    }

    function main() {
        drawText("Hello, world!", [100, 50], true)
    }

.. _R092:

|CB_R| #92: Nested functions are not supported
----------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support nested functions. Use lambdas instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function addNum(a: number, b: number): void {

        // nested function:
        function logToConsole(message: String): void {
            console.log(message)
        }

        let result = a + b

        // Invoking the nested function:
        logToConsole("result is " + result)
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function addNum(a: number, b: number): void {

        // Use lambda instead of a nested function:
        let logToConsole: (message: String): void = (message: String): void => {
            console.println(message)
        }

        let result = a + b

        logToConsole("result is " + result)
    }

.. _R093:

|CB_R| #93: Using ``this`` inside stand-alone functions is not supported
------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the usage of ``this`` inside stand-alone functions.
``this`` can be used in methods only.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function foo(i: number) {
        this.count = i
    }

    class A {
        count: number = 1
        m = foo
    }

    let a = new A()
    console.log(a.count) // prints "1"
    a.m(2)
    console.log(a.count) // prints "2"


|CB_OK|
~~~~~~~

.. code-block:: typescript

    class A {
        count: number = 1
        m(i: number): void {
            this.count = i
        }
    }

    function main(): void {
        let a = new A()
        console.log(a.count)  // prints "1"
        a.m(2)
        console.log(a.count)  // prints "2"
    }

.. _R094:

|CB_R| #94: Generator functions are not supported
-------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support generator functions.
Use the ``async`` / ``await`` mechanism for multitasking.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function* counter(start: number, end: number) {
        for (let i = start; i <= end; i++) {
            yield i
        }
    }

    for (let num of counter(1, 5)) {
        console.log(num)
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    for (let i = 1; i <= 5; ++i) {
        console.log(i)
    }

.. _R095:

|CB_R| #95: Asynchronous functions are partially supported
----------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| partially supports asynchronous functions.
Using the ``launch`` mechanism (|LANG| extension to |TS|)
is recommended for multitasking.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    async function sum(numbers: number[]): Promise<number> {
        let sum = 0
        for (let num of numbers) {
            sum += await num
        }
        return sum
    }

    ...
    const result = await sum(5, 10)
    ...

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function sum(numbers: number[]): number {
        let sum = 0
        for (let i = 0; i < numbers.length; ++i) {
            sum += numbers[i]
        }
        return sum
    }

    ...
    const result = launch sum(5, 10)  // `result` will be of type `Promise<number>`
    ...

NOT recommended:

.. code-block:: typescript

    async function sum(numbers: number[]): Promise<number> {
        let sum = 0
        for (let i = 0; i < numbers.length; ++i) {
            sum += await numbers[i]
        }
        return sum
    }

    ...
    const result = sum(5, 10)
    ...

.. _R096:

|CB_R| #96: Type guarding is supported with ``instanceof`` and ``as``
---------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the ``is`` operator, which must be replaced by the
``instanceof`` operator. Note that the fields of an object must be cast to the
appropriate type with the ``as`` operator before use.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Foo {
        foo: number = 0
        common: string = ""
    }

    class Bar {
        bar: number = 0
        common: string = ""
    }

    function isFoo(arg: any): arg is Foo {
        return arg.foo !== undefined
    }

    function doStuff(arg: Foo | Bar) {
        if (isFoo(arg)) {
            console.log(arg.foo)    // OK
            console.log(arg.bar)    // Error!
        }
        else {
            console.log(arg.foo)    // Error!
            console.log(arg.bar)    // OK
        }
    }

    doStuff({ foo: 123, common: '123' })
    doStuff({ bar: 123, common: '123' })

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Foo {
        foo: number = 0
        common: string = ""
    }

    class Bar {
        bar: number = 0
        common: string = ""
    }

    function isFoo(arg: Object): boolean {
        return arg instanceof Foo
    }

    function doStuff(arg: Object): void {
        if (isFoo(arg)) {
            let fooArg = arg as Foo
            console.log(fooArg.foo)     // OK
            console.log(arg.bar)        // Error!
        }
        else {
            let barArg = arg as Bar
            console.log(arg.foo)        // Error!
            console.log(barArg.bar)     // OK
        }
    }

    function main(): void {
        doStuff(new Foo())
        doStuff(new Bar())
    }

.. _R098:

|CB_R| #98: Spreading an array into function arguments is not supported
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the spread operator.
"Unpack" data from an array to a callee manually.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    function foo(x, y, z) {}

    let args = [0, 1, 2]
    foo(...args)

|CB_OK|
~~~~~~~

.. code-block:: typescript

    function foo(x: number, y: number, z: number): void {}

    function main(): void {
        let args: number[] = [0, 1, 2]
        foo(args[0], args[1], args[2])
    }

.. _R099:

|CB_R| #99: Spread operator is not supported
--------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the spread operator.
"Unpack" data from arrays indices manually where necessary.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    let list = [1, 2]
    list = [...list, 3, 4]

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let list: number[] = [1, 2]
    list = [list[0], list[1], 3, 4]

.. _R100:

|CB_R| #100: Spreading an object is not supported
---------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the spread operator.
"Unpack" data from an object to a callee manually, field by field.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    const point2d = {x: 1, y: 2}
    const point3d = {...point2d, z: 3}

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Point2D {
        x: number
        y: number

        constructor(x: number, y: number) {
            this.x = x
            this.y = y
        }
    }

    class Point3D {
        x: number
        y: number
        z: number

        constructor(x: number, y: number, z: number) {
            this.x = x
            this.y = y
            this.z = z
        }
    }

    function main(): void {
        const point2d = new Point2D(1, 2)
        const point3d = new Point3D(point2d.x, point2d.y, 3)
    }

|CB_R| #101: Interfaces with optional properties and call signatures are not supported
--------------------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support interfaces with optional properties and interfaces
with call signatures.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    // Interface with optional properties
    interface Person {
      firstName: string
      lastName: string
      age?: number
    }

    // Interface with call signature
    interface Greet {
      (name: string): string
    }

|CB_OK|
~~~~~~~

.. code:: typescript

    // Use nullable type instead of optional property
    interface Person {
      firstName: string
      lastName: string
      age: number | null
    }

    // Use a method signature instead of call signature
    interface Greet {
      action (name: string): string
    }



|CB_R| #102: Interface declarations (extends same property)
-----------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not allow an interface to contain two methods with signatures that
are  not distinguishable, e.g., two methods that have the same parameter lists
but different return types.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    interface Mover {
        getStatus(): { speed: number }
    }
    interface Shaker {
        getStatus(): { frequency: number }
    }

    interface MoverShaker extends Mover, Shaker {
        getStatus(): { speed: number; frequency: number }
    }

    class C implements MoverShaker {
        private speed: number = 0
        private frequency: number = 0

        getStatus() {
            return { speed: this.speed, frequency: this.frequency }
        }
    }

In |TS|, an interface that extends ``Mover`` and ``Shaker`` must declare a
new ``getStatus`` with a combined result type. It is not allowed in |LANG|.

.. _R103:

|CB_R| #103: Declaration merging is not supported
-------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support merging declratations. All definitions of classes,
interfaces and so on must be kept compact in the code base.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    interface Document {
        createElement(tagName: any): Element
    }

    interface Document {
        createElement(tagName: string): HTMLElement
    }

    interface Document {
        createElement(tagName: number): HTMLDivElement
        createElement(tagName: boolean): HTMLSpanElement
        createElement(tagName: string, value: number): HTMLCanvasElement
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface Document {
        createElement(tagName: number): HTMLDivElement
        createElement(tagName: boolean): HTMLSpanElement
        createElement(tagName: string, value: number): HTMLCanvasElement
        createElement(tagName: string): HTMLElement
        createElement(tagName: Object): Element
    }

.. _R104:

|CB_R| #104: Interfaces cannot extend classes
---------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support interfaces that extend classes. Interfaces can extend
only interfaces.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Control {
        state: number = 0
    }

    interface SelectableControl extends Control {
        select(): void
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    interface Control {
        state: number = 0
    }

    interface SelectableControl extends Control {
        select(): void
    }

.. _R105:

|CB_R| #105: Property-based runtime type checks are not supported
-----------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| requires that object layout is determined in compile-time and cannot
be changed at runtime. There for no runtime property-based checks are supported.
If you need to do a type cast, use ``as`` operator and use desired properties
and methods. If some property doesn't exist then an attempt to reference it
will result in a compile-time error.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class A {
        foo() {}
        bar() {}
    }

    function getSomeObject() {
        return new A()
    }

    let obj: any = getSomeObject()
    if (obj && obj.foo && obj.bar) {
        console.log("Yes")  // prints "Yes" in this example
    } else {
        console.log("No")
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class A {
        foo(): void {}
        bar(): void {}
    }

    function getSomeObject(): A {
        return new A()
    }

    function main(): void {
        let tmp: Object = getSomeObject()
        let obj: A = tmp as A
        obj.foo()       // OK
        obj.bar()       // OK
        obj.some_foo()  // Compile-time error: Method some_foo does not exist on this type
    }

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R052`
* :ref:`R059`
* :ref:`R060`
* :ref:`R066`
* :ref:`R109`

.. _R106:

|CB_R| #106: Constructor function type is not supported
-------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the usage of the constructor function type.
Use lambdas instead, as they can be generalized to several types of objects.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Person {
        constructor(
            name: string,
            age: number
        ) {}
    }

    type PersonConstructor = new (name: string, age: number) => Person

    function createPerson(Ctor: PersonConstructor, name: string, age: number): Person {
        return new Ctor(name, age)
    }

    const person = createPerson(Person, 'John', 30)

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Person {
        constructor(
            name: string,
            age: number
        ) {}
    }

    let PersonConstructor: (name: string, age: number): Person = (name: string, age: number): Person => {
        return new Person(name, age)
    }

    function createPerson(Ctor: (name: string, age: number): Person, name: string, age: number): Person {
        return PersonConstructor(name, age)
    }

    function main(): void {
        const person = createPerson(PersonConstructor, "John", 30)
    }

.. _R107:

|CB_R| #107: Constructor declarations
-------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support optional parameters in constructors.
Constructors are not inherited from a superclass to a subclass. Use overloading
constructors instead of constructors with optional parameters:

|CB_BAD|
~~~~~~~~

.. code:: typescript

    class Foo {
      constructor(bar: string = 'default', baz?: number) {}
    }

|CB_OK|
~~~~~~~

.. code:: typescript

    class Foo {
        constructor(bar: string) {}
        constructor(bar: string, baz: number) {}
    }

|CB_RULE|
~~~~~~~~~

In |LANG|, constructors are not inherited from a superclass.

|CB_BAD|
~~~~~~~~

The constructor defined in a superclass can be used in a subclass.

.. code:: typescript

    class C1 {
        constructor(bar: string, baz: number) {}
    }
    class C2 extends Foo {}

    let c = C2("a", "b")

|CB_OK|
~~~~~~~

A subclass must define its own constructor.

.. code:: typescript

    class C1 {
        constructor(bar: string, baz: number) {}
    }
    class C2 extends Foo {
        constructor(bar: string, baz: number) {
            super(bar, string)
        }
    }

    let c = C2("a", "b")

|CB_SEE|
~~~~~~~~

* :ref:`R015`

.. _R108:

|CB_R| #108: Overloaded constructors with shared body are not supported
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support sharing a body between function overloads.
The shared body feature for ``constructor`` is not supported, either.
Overload constructor with a separate body for each signature.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Person {
        name: string
        age: number

        constructor(name: string, age?: number) {
            this.name = name
            if (age) {
                this.age = age
            } else {
                this.age = 0
            }
        }
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Person {
        name: string
        age: number

        constructor(name: string, age: number) {
            this.name = name
            this.age = age
        }

        constructor(name: string) {
            this.name = name
            this.age = 0
        }
    }

.. _R109:

|CB_R| #109: Dynamic property declaration is not supported
----------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support dynamic property declaration. All object properties must
be declared immediately in the class. While it can be replaced with an array
of objects, it is still better to adhere to the static language paradigm and
declare fields, their names and types explicitly.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    class Person {
        name: string = ""
        age: number = 0
        [key: string]: string | number
    }

    const person: Person = {
        name: "John",
        age: 30,
        email: "john@example.com",
        phone: 1234567890,
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    class Person {
        name: string
        age: number
        email: string
        phone: number

        constructor(name: string, age: number, email: string, phone: number) {
            this.name = name
            this.age = age
            this.email = email
            this.phone = phone
        }
    }

    function main(): void {
        const person: Person = new Person("John", 30, "john@example.com", 1234567890)
    }

|CB_SEE|
~~~~~~~~

* :ref:`R001`
* :ref:`R002`
* :ref:`R052`
* :ref:`R059`
* :ref:`R060`
* :ref:`R066`
* :ref:`R105`

.. _R111:

|CB_R| #111: Explicit values for enumeration constants are not supported
------------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

Currently, |LANG| does not support assigning explicit values for ``enums``.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    enum E {
        A,
        B,
        C = 10,
        D
    }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    enum E {
        A,
        B,
        C = 10,  // Compile-time error: assigning out of order values for enums is not supported
        D
    }

    enum E_fixed {
        A,
        B,
        C,   // OK
        D
    }

.. _R112:

.. _R113:

|CB_R| #113: ``enum`` declaration merging is not supported
----------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support merging declratations for ``enum``.
The declaration of each ``enum`` must be kept compact in the code base.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    enum Color {
        RED,
        GREEN
    }
    enum Color {
        YELLOW
    }
    enum Color {
        BLACK,
        BLUE
    }

|CB_OK|
~~~~~~~

.. code:: typescript

    enum Color {
        RED,
        GREEN,
        YELLOW,
        BLACK,
        BLUE
    }

.. _R114:

|CB_R| #114: Namespaces cannot be used as objects
-------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support the usage of namespaces as objects.
Classes or modules can be interpreted as analogues of namespaces.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    namespace MyNamespace {
        export let x: number
    }

    let m = MyNamespace
    m.x = 2

|CB_OK|
~~~~~~~

.. code-block:: typescript

    namespace MyNamespace {
        export let x: number
    }

    MyNamespace.x = 2

.. _R115:

|CB_R| #115: Scripts and modules
--------------------------------

|CB_RULE|
~~~~~~~~~

In general, scripts and modules in |LANG| are very close to |TS|.
Differences are described in separate recipes.

|CB_SEE|
~~~~~~~~

* :ref:`R117`
* :ref:`R118`
* :ref:`R119`
* :ref:`R120`
* :ref:`R121`
* :ref:`R122`
* :ref:`R124`
* :ref:`R125`
* :ref:`R126`

.. _R116:

|CB_R| #116: Non-declaration statements in namespaces are not supported
-----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support statements in namespaces. Use a function to exectute statements.

|CB_BAD|
~~~~~~~~~

.. code:: typescript

    namespace A {
        export let x: number
        x = 1
    }

|CB_OK|
~~~~~~~~~

Initialization function should be called to execute statements.

.. code:: typescript

    namespace A {
        export let x: number

        export function init() {
          x = 1
        }
    }
    A.init()


.. _R117:

|CB_R| #117: Statement as top-level element
-------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support statements as top-level elements. Statements must be
placed in a block ``{}``.

|CB_BAD|
~~~~~~~~~

.. code:: typescript

    let a = 1
    let b = 2
    if (b == a) {
        console.log("a EQ b")
    } else {
        console.log("a NEQ b")
    }

|CB_OK|
~~~~~~~~~

.. code:: typescript

    // A block can be a top-level element,
    // put statements inside one or several blocks:
    {
        let a = 1
        let b = 2
    }

    {
        if (b == a) {
            console.log("a EQ b")
        } else {
            console.log("a NEQ b")
        }
    }


.. _R118:

|CB_R| #118: Special import type declarations are not supported
---------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not have a special notation for importing types.
Use ordinary import instead.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    // Re-using the same import
    import { APIResponseType } from "./api"

    // Explicitly use import type
    import type { APIResponseType } from "./api"

|CB_OK|
~~~~~~~

.. code:: typescript

    import { APIResponseType } from "./api"

|CB_SEE|
~~~~~~~~

* :ref:`R119`
* :ref:`R120`
* :ref:`R121`

.. _R119:

|CB_R| #119: Importing a module for side-effects only is not supported
----------------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support global variables like ``window`` to avoid
side-effects during module importing. All variables marked as export can be
accessed through the ``*`` syntax.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    // === module at "path/to/module.ts"
    export const EXAMPLE_VALUE = 42

    // Set a global variable
    window.MY_GLOBAL_VAR = "Hello, world!"

    // ==== using this module:
    import "path/to/module"

|CB_OK|
~~~~~~~

.. code:: typescript

    import * from "path/to/module"

.. _R120:

|CB_R| #120: ``import default as ...`` is not supported
-------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``import default as ...`` syntax.
Use explicit ``import ... from ...`` instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    import { default as d } from "mod"

|CB_OK|
~~~~~~~

.. code-block:: typescript

    import d from "mod"

|CB_SEE|
~~~~~~~~

* :ref:`R122`

.. _R121:

|CB_R| #121: ``require`` is not supported
-----------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support importing via ``require``. Use ``import`` instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    import m = require("mod")

|CB_OK|
~~~~~~~

.. code-block:: typescript

    import * as m from "mod"

.. _R122:

|CB_R| #122: ``export default`` is not supported
------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``export default``.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // file1.ts
    export default class MyClass {
        // ...
    }

    // file2.ts
    // Can write just `MyClass` instead of `{ MyClass }` in case of default export
    import MyClass from './file1'

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // module1
    export class MyClass {
        // ...
    }

    // module2
    // Use explicit name in import
    import { MyClass } from "./module1"

|CB_SEE|
~~~~~~~~

* :ref:`R120`

.. _R124:

|CB_R| #124: Export list declaration is not supported
-----------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support syntax of export list declarations. All exported
entities must be explicitly annotated with the ``export`` keyword.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    export { x }
    export { x } from "mod"
    export { x, y as b, z as c }

|CB_OK|
~~~~~~~

.. code-block:: typescript

    let x = 1
    class MyClass {}
    export let y = x, z: number = 2
    export RenamedClass = MyClass

|CB_SEE|
~~~~~~~~

* :ref:`R125`
* :ref:`R126`

.. _R125:

|CB_R| #125: Re-exporting is not supported
------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support re-exporting. All desired entities must be
imported explicitly from the modules that export them.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // module1
    export class MyClass {
        // ...
    }

    // module2
    export { MyClass } from "module1"

    // consumer module
    import { MyClass } from "module2"

    const myInstance = new MyClass()

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // module1
    export class MyClass {
      // ...
    }

    // module2
    // some stuff

    // consumer module
    import MyClass from "module1"
    import * from "module2"

    const myInstance = new MyClass()

|CB_SEE|
~~~~~~~~

* :ref:`R124`
* :ref:`R126`

.. _R126:

|CB_R| #126: ``export = ...`` assignment is not supported
---------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not support ``export = ...`` syntax.
Use regular ``export`` / ``import`` instead.

|CB_BAD|
~~~~~~~~

.. code-block:: typescript

    // module1
    export = Point

    class Point {
        constructor(x: number, y: number) {}
        static origin = new Point(0, 0)
    }

    // module2
    import Pt = require("module1")

    let p = Pt.origin

|CB_OK|
~~~~~~~

.. code-block:: typescript

    // module1
    export class Point {
        constructor(x: number, y: number) {}
        static origin = new Point(0, 0)
    }

    // module2
    import * as Pt from "module1"

    let p = Pt.origin

|CB_SEE|
~~~~~~~~

* :ref:`R124`
* :ref:`R125`


.. _R127:

|CB_R| #127: Special export type declarations are not supported
---------------------------------------------------------------

|CB_RULE|
~~~~~~~~~

|LANG| does not have a special notation for exporting types.
Use ordinary export instead.

|CB_BAD|
~~~~~~~~

.. code:: typescript

    class C {}
    export type { C }

|CB_OK|
~~~~~~~

.. code:: typescript

    export class C {}
    
