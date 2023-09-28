/* 
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd. 
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

export var cookBookMsg: string[] = []; 

export var cookBookTag: string[] = []; 

cookBookMsg[ 1 ] = " \
 #1: Objects with property names that are not identifiers are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support Objects with name properties that are numbers or \
strings. Use classes to access data by property names. Use arrays to access data \
by numeric indices. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;var x = {\"name\": 1, 2: 3}<br> \
<br> \
&nbsp;&nbsp;&nbsp;console.log(x[\"name\"])<br> \
&nbsp;&nbsp;&nbsp;console.log(x[2])<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public name: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = {name: 1}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(x.name)<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = [1, 2, 3]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(y[2])<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// If you still need a container to store keys of different types,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// use Map<Object, some_type>:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let z = new Map<Object, number>()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;z.set(\"name\", 1)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;z.set(2, 2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(z.get(\"name\"))<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(z.get(2))<br> \
<br> \
</code><br> \
";

cookBookMsg[ 2 ] = " \
 #2: <code>Symbol()</code> API is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>Symbol()</code> API. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
TypeScript has <code>Symbol()</code> API, which can be used among other things to generate \
unique property names at runtime: \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const sym = Symbol()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let o = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[sym]: \"value\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
ArkTS does not support <code>Symbol()</code> API because its most popular use cases \
make no sense in the statically typed environment. In particular, the object \
layout is defined at compile time and cannot be changed at runtime. \
 \
";

cookBookMsg[ 3 ] = " \
 #3: Private '#' identifiers are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not private identifiers started with <code>#</code> symbol, use <code>private</code> keyword instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private foo = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 4 ] = " \
 #4: Use unique names for types, namespaces, etc.<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Names for types, namespaces and so on must be unique and distinct from other \
names, e.g., variable names. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let X: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type X = number[] // Type alias with the same name as the variable<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let X: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type T = number[] // X is not allowed here to avoid name collisions<br> \
<br> \
</code><br> \
";

cookBookMsg[ 5 ] = " \
 #5: Use <code>let</code> instead of <code>var</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>var</code>, always use <code>let</code> instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(shouldInitialize: boolean) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (shouldInitialize) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;var x = 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(f(true))  // 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(f(false)) // undefined<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let upper_let = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;{<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;var scoped_var = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let scoped_let = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;upper_let = 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;scoped_var = 5 // Visible<br> \
&nbsp;&nbsp;&nbsp;&nbsp;scoped_let = 5 // Compile-time error<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(shouldInitialize: boolean): Object {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let x: Object = new Object();<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (shouldInitialize) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x = 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;console.log(f(true));  // 10<br> \
&nbsp;&nbsp;&nbsp;console.log(f(false)); // {}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let upper_let = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let scoped_var = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;{<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let scoped_let = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;upper_let = 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;scoped_var = 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;scoped_let = 5 // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 8 ] = " \
 #8: Use explicit types instead of <code>any</code>, <code>undefined</code>, <code>unknown</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>any</code>, <code>undefined</code>, and <code>unknown</code> types. \
Specify types explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(x) // undefined<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var y: any<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(y) // undefined<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// All variables should have their types specified explicitly:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: Object = {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(x) // {}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 9 ] = " \
 #9: You can extend your TypeScript code with more numeric types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports different numeric types on top of just <code>number</code>. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
TypeScript supports <code>number</code> as the only numeric type: \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: number = 1<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
ArkTS supports several numeric types: \
 \
+-----------+----------+-------------------------------------------------------------+ \
| Type      | Size     | Range                                                       | \
+===========+==========+=============================================================+ \
|<code>byte</code>   | 8 bits   |<code>[-128 .. 127]</code>                                            | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>short</code>  | 16 bits  |<code>[-32,768 .. 32,767]</code>                                      | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>int</code>    | 32 bits  |<code>[-2,147,483,648 .. 2,147,483,647]</code>                        | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>long</code>   | 64 bits  |<code>[-9,223,372,036,854,775,808 .. 9,223,372,036,854,775,807]</code>| \
+-----------+----------+-------------------------------------------------------------+ \
|<code>ubyte</code>  | 8 bits   |<code>[0 .. 255]</code>                                               | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>ushort</code> | 16 bits  |<code>[0 .. 65,535]</code>                                            | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>uint</code>   | 32 bits  |<code>[0 .. 4,294,967,295]</code>                                     | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>ulong</code>  | 64 bits  |<code>[0 .. 18,446,744,073,709,551,615]</code>                        | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>float</code>  | 32 bits  |<code>3.4E +/- 38 (7 digits)</code>                                   | \
+-----------+----------+-------------------------------------------------------------+ \
|<code>double</code> | 64 bits  |<code>1.7E +/- 308 (15 digits)</code>                                 | \
+-----------+----------+-------------------------------------------------------------+ \
 \
Additionally, ArkTS supports the following types: \
 \
* Character type <code>char</code> (the range of values is the same as <code>ushort</code>) \
* Boolean type <code>boolean</code> (values: <code>true</code>, <code>false</code>) \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: int = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y: boolean = true<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let z: char = 'a'<br> \
<br> \
</code><br> \
";

cookBookMsg[ 10 ] = " \
 #10: Use <code>long</code> instead of <code>bigint</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Use <code>long</code> to work with 64-bit integers. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
TypeScript supports <code>bigint</code> data type, but this feature is available only since \
ES2020 and requires <code>n</code> suffix for numeric literals: \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: bigint = 1n<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
ArkTS provides <code>long</code> data type to work with 64-bit \
integers, <code>n</code> suffix is not supported: \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: long = 1<br> \
<br> \
</code><br> \
";

cookBookMsg[ 11 ] = " \
 #11: Use <code>enum</code> instead of string literal types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support string literal types. Use <code>enum</code> instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type Easing = \"ease-in\" | \"ease-out\" | \"ease-in-out\";<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Easing {EaseIn, EaseOut, EaseInOut}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 12 ] = " \
 #12: Use <code>T[]</code> instead of <code>Array<T></code> to declare arrays<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
In TypeScript, arrays can be declared as either <code>Array<T></code> or <code>T[]</code>. Currently, \
ArkTS supports only the second syntax for array declaration. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// These are equivalent in TypeScript:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y: Array<string> = [\"1\", \"2\", \"3\"]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let x: string[] = [\"1\", \"2\", \"3\"];<br> \
&nbsp;&nbsp;&nbsp;let y: string[] = [\"1\", \"2\", \"3\"]; // Array<string> is not supported currently<br> \
<br> \
</code><br> \
";

cookBookMsg[ 13 ] = " \
 #13: Use <code>Object[]</code> instead of tuples<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support tuples. You can use arrays of <code>Object</code> \
(<code>Object[]</code>) to emulate tuples. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var t: [number, string] = [3, \"three\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var n = t[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var s = t[1]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let t: Object[] = [3, \"three\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let n = t[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let s = t[1]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 14 ] = " \
 #14: Use <code>class</code> instead of a type with call signature<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support call signatures in object types. Use classes instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type DescribableFunction = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;description: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(someArg: number): string // call signature<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doSomething(fn: DescribableFunction): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(fn.description + \" returned \" + fn(6))<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class DescribableFunction {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;description: string;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public invoke(someArg: number): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return someArg.toString()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.description = \"desc\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doSomething(fn: DescribableFunction): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(fn.description + \" returned \" + fn.invoke(6))<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;doSomething(new DescribableFunction());<br> \
<br> \
</code><br> \
";

cookBookMsg[ 15 ] = " \
 #15: Use <code>class</code> instead of a type with constructor signature<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support constructor signatures in object types. Use classes \
instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class SomeObject {}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type SomeConstructor = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;new (s: string): SomeObject<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function fn(ctor: SomeConstructor) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new ctor(\"hello\");<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class SomeObject {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public f: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor (s: string) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.f = s<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function fn(s: string): SomeObject {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new SomeObject(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 16 ] = " \
 #16: Only one static block is supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not allow to have sevaral static block for class initialization, combine static blocks statements to the one static block. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static s: string<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C.s = \"aa\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C.s = C.s + \"bb\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static s: string<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C.s = \"aa\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C.s = C.s + \"bb\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 17 ] = " \
 #17: Indexed signatures are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not allow indexed signatures, use arrays instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Interface with an indexed signature:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface StringArray {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[index: number]: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const myArray: StringArray = getStringArray()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const secondItem = myArray[1]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public f: string[]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let myArray: X = new X()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const secondItem = myArray.f[1]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 18 ] = " \
 #18: Use <code>Object</code> instead of union types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS provides limited support for union types; \
nullable types are supported only in the form <code>T | null</code>. \
You can use <code>Object</code> to emulate the behaviour of the unions in standard TypeScript. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var x: string | number<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: Object<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(x)<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = \"2\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(x)<br> \
<br> \
</code><br> \
";

cookBookMsg[ 19 ] = " \
 #19: Use inheritance instead of intersection types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support intersection types. You can use inheritance \
as a work-around. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Identity {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;id: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Contact {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;email: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;phone: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type Employee = Identity & Contact<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Identity {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;id: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Contact {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;email: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;phone: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Employee extends Identity,  Contact {}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 20 ] = " \
 #20: Default values for type parameters in generics are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support default values for type parameters. Use \
generic parameters without default values instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Declare a generic function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo<N = number, S = string>() {...}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Call the function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo() // foo<number, string>() will be called<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Declare a generic function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo<N, S>() {...}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Call the function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo<number, string>() // N and S should be specified explicitly<br> \
<br> \
</code><br> \
";

cookBookMsg[ 21 ] = " \
 #21: Returning <code>this</code> type is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the returning <code>this</code> type. Use explicit type instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface ListItem {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;getHead(): this<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface ListItem {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;getHead(): ListItem<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 23 ] = " \
 #22: Conditional types are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support conditional type aliases. Introduce a new type with constraints explicitly or rewrite logic with use of <code>Object</code>. \
<code>infer</code> keyword is not supported. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type X<T> = T extends number ? T : never<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type Y<T> = T extends Array<infer Item> ? Item : never<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Provide explicit contraints within type alias<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type X1<T extends number> = T<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Rewrite with Object. Less type control, need more type checks for safety<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type X2<T> = Object<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Item has to be used as a generic parameter and need to be properly instantiated<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type YI<Item, T extends Array<Item>> = Item<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 24 ] = " \
 #24: Optional arguments are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support optional parameters. Specify an \
optional parameter as a parameter of a nullable type with the \
default value <code>null</code>. Default parameter values are supported for all types. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// x is an optional parameter:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(x?: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x) // log undefined or number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// x is a required parameter with the default value:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function g(x: number = 1) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Optional parameters are not supported,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// but you can assign a default value ``null`` for the parameter:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(x: number | null = null) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x); // log null or number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// x is a required argument with the default value:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function g(x: number = 1) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x);<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 25 ] = " \
 #25: Declaring fields in <code>constructor</code> is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support declaring class fields in the <code>constructor</code>. \
You must declare them inside the <code>class</code> declaration instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;protected ssn: string,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private firstName: string,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private lastName: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.ssn = ssn<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.firstName = firstName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.lastName = lastName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;getFullName(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return this.firstName + \" \" + this.lastName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;protected ssn: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private firstName: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private lastName: string<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(ssn: string, firstName: string, lastName: string) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.ssn = ssn<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.firstName = firstName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.lastName = lastName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;getFullName(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return this.firstName + \" \" + this.lastName<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 26 ] = " \
 #26: Specialized signatures are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support specialized signatures as a form of \
overloading with special type notation (string literal instead of type). \
Use other patterns (e.g., interfaces) instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;inteface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagname: \"div\"): HTMLDivElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagname: \"span\"): HTMLDivElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class HTMLElement {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class HTMLDivElement extends HTMLElement {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class HTMLSpanElement extends HTMLElement {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string): HTMLElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class D implements Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string): HTMLElement {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;switch (tagname) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case \"div\": return new HTMLDivElement()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case \"span\": return new HTMLSpanElement()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 27 ] = " \
 #27: Construct signatures not supported in interfaces<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support construct signatures. Use methods instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface I {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;new (s: string): I<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function fn(i: I) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new i(\"hello\");<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface I {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;create(s: string): I<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function fn(i: I) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return i.create(\"hello\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 28 ] = " \
 #28: Indexed access types are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support indexed access types. Use the type name instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type Point = {x: number, y: number}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type N = Point[\"x\"] // is equal to number<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {x: number = 0; y: number = 0}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type N = number<br> \
<br> \
</code><br> \
";

cookBookMsg[ 29 ] = " \
 #29: Indexed access is not supported for fields<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support indexed access for class fields. Use dot notation instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {x: number = 0; y: number = 0}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p: Point = {x: 1, y: 2}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = p[\"x\"]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {x: number = 0; y: number = 0}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p: Point = {x: 1, y: 2}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = p.x<br> \
<br> \
</code><br> \
";

cookBookMsg[ 30 ] = " \
 #30: Structural identity is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support structural identity, i.e., the compiler \
cannot compare two types' public APIs and decide whether such types are \
identical. Use other mechanisms (inheritance, interfaces or type aliases) \
instead. \
 \
In TypeScript, types <code>X</code> and <code>Y</code> are equal (interchangeble), while in ArkTS \
they are not. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;f(): string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Y { // Y is equal to X<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;f(): string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
ArkTS does not support structural identity. In the static environment the \
compiler checks if two classes or interfaces are equal, but there is no way \
to compare unrelated (by inheritance or interface) classes that are \
structurally equivalent. \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;f(): string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type Y = X // Y is equal to X<br> \
<br> \
</code><br> \
";

cookBookMsg[ 31 ] = " \
 #31: Structural typing is not supported for subtyping / supertyping<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not check structural equivalence for type inference, i.e., \
the compiler cannot compare two types' public APIs and decide whether such types \
are identical. \
Use other mechanisms (inheritance or interfaces) instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = new X()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = new Y()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign X to Y\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;y = x<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign Y to X\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = y<br> \
<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Y is derived from X, which explicitly set subtype / supertype relations:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y extends X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;super()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = new X()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = new Y()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign X to Y\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;y = x // ok, X is the super class of X<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Cannot assign Y to X<br> \
&nbsp;&nbsp;&nbsp;&nbsp;//x = y - compile-time error<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 32 ] = " \
 #32: Structural typing is not supported for assignability checks<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not check structural equivalence when checking if types \
are assignable to each other, i.e., the compiler cannot compare two types' \
public APIs and decide whether such types are identical. Use other mechanisms \
(inheritance or interfaces) instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = new X()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = new Y()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign X to Y\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;y = x<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign Y to X\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = y<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// X implements interface Z, which makes relation between X and Y explicit.<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X implements Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Y implements interface Z, which makes relation between X and Y explicit.<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y implements Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: Z = new X()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y: Z = new Y()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign X to Y\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;y = x // ok, both are of the same type<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Assign Y to X\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = y // ok, both are of the same type<br> \
<br> \
</code><br> \
";

cookBookMsg[ 33 ] = " \
 #33: Optional properties are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support optional properties. Use properties with default values. \
Use properties of nullable types and the default <code>null</code> value to distinguish \
whether a value is set or not. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface CompilerOptions {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;strict?: boolean<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sourcePath?: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;targetPath?: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var options: CompilerOptions = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;strict: true,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sourcepath: \"./src\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if option.targetPath == undefined {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// set default<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface CompilerOptions {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;strict: boolean = false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sourcePath: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;targetPath: string | null = null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let options: CompilerOptions = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;strict: true,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sourcepath: \"./src\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if option.targetPath == null {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// set default<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 34 ] = " \
 #34: Generic functions must be called with explicit type specialization<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support inference of type parameters in case of calls \
to generic functions. If a function is declared generic, all calls must specify \
type parameters explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function choose<T>(x: T, y: T): T {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return Math.random() < 0.5 ? x : y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = choose(10, 20) // Ok<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = choose(\"10\", 20) // Compile-time error<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function choose<T>(x: T, y: T): T {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return Math.random() < 0.5 ? x : y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = choose<number>(10, 20) // Ok<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = choose<number>(\"10\", 20) // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 35 ] = " \
 #35: Structural typing is not supported for type inference<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support structural typing, i.e., the compiler cannot \
compare two types' public APIs and decide whether such types are identical. \
Use inheritance and interfaces to specify the relation between the types \
explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X  {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private s: string<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor (f: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = f<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.s = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public say(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"X = \", this.foo)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor (f: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = f<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public say(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Y = \", this.foo)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function bar(z: X): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;z.say()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// X and Y are equivalent because their public API is equivalent.<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Thus the second call is allowed:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;bar(new X(1));<br> \
&nbsp;&nbsp;&nbsp;&nbsp;bar(new Y(2));<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;say(): void<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class X implements Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private s: string<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor (f: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = f<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.s = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public say(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"X = \", this.foo)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Y implements Z {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public foo: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor (f: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.foo = f<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public say(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Y = \", this.foo)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function bar(z: Z): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;z.say()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// X and Y implement the same interface Z, thus both calls are allowed:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;bar(new X(1))<br> \
&nbsp;&nbsp;&nbsp;&nbsp;bar(new Y(2))<br> \
<br> \
</code><br> \
";

cookBookMsg[ 36 ] = " \
 #36: Type widening is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support widened types because in most cases type widening \
is applied to the currently unsupported types <code>any</code>, <code>unknown</code> \
and <code>undefined</code>. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var a = null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var b = undefined<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var c = {c: 0, y: null}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var d = [null, undefined]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public c: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public y: Object | null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: Object | null = null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b: Object<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c: C = {c: 0, y: null}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d: Object[] = [null, null]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 37 ] = " \
 #37: RegExp literals are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support RegExp literals. Use library call with string \
literals instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let regex: RegExp = /bc*d/<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let regex: RegExp = new RegExp(\"/bc*d/\")<br> \
<br> \
</code><br> \
";

cookBookMsg[ 38 ] = " \
 #38: Object literal must correspond to explicitly declared class or interface<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the usage of object literals if the compiler can infer \
to what classes or interfaces such literals correspond to.  \
Otherwise, a compile-time error occurs.   \
 \
The class or interface can be specified as a type annotation for a variable. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let x = {f: 1}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class O {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;f: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: O = {f: 1} // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = {f: 1} // Compile-time error, cannot infer object literal type<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let z: Object = {f: 2} // Compile-time error, class 'Object' does not have field 'f'<br> \
<br> \
</code><br> \
";

cookBookMsg[ 39 ] = " \
 #39: Object literals must correspond to explicitly declared class or interface<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the usage of object literals if the compiler can infer to what \
classes or interfaces such literals correspond to. Otherwise, a compile-time \
error occurs. \
 \
The class or interface can be inferred from a type of the corresponding function parameter. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(x: any) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo({f: 1})<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class S {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;f: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(s: S) {}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo({f: 2})  // ok<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo({ff: 2}) // Compile-time error, class 'S' does not have field 'ff'<br> \
<br> \
</code><br> \
";

cookBookMsg[ 40 ] = " \
 #40: Object literals cannot be used as type declarations<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the usage of object literals to declare \
types in place. Declare classes and interfaces explicitly instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let o: {x: number, y: number} = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: 2,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: 3<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type T = G<{x: number, y: number}><br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class O {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let o: O = {x: 2, y: 3}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type T = G<O><br> \
<br> \
</code><br> \
";

cookBookMsg[ 42 ] = " \
 #42: Array literals must correspond to known array types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the usage of array literals if the compiler can infer \
to what array types such literals correspond to. Otherwise, a compile-time \
error occurs. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let x = [\"aa\", \"bb\"]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;let x: string[] = [\"aa\", \"bb\"]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 43 ] = " \
 #43: Untyped array literals are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the usage of untyped array literals.  The type of an \
array element must be inferred from the context. Use the type <code>Object</code> to \
define mixed types array. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = [1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = [1, \"aa\"]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: Object[] = [new Int(1), new Int(2)]<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Implicit boxing of primitive int to object Int<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x1: Object[] = [1, 2]<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y: Object[] = [1, \"aa\"]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 44 ] = " \
 #44: Template literals are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support template literals. You may use a <code>+</code> \
concatenation as a work-around. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const a = 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const b = 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(`Fifteen is ${a + b}`)<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const a = 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const b = 10<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// (a + b) is converted to Int and then toString() method is called:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Fifteen is \" + (a + b))<br> \
<br> \
</code><br> \
";

cookBookMsg[ 45 ] = " \
 #45: Lambdas require explicit type annotation for parameters<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS requires the types of lambda parameters  \
to be explicitly specified. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = (s) => { // type any is assumed<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
Explicit types for lambda parameters are mandatory. \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f =<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(s: string) => {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 46 ] = " \
 #46: Use arrow functions instead of function expressions<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support function expressions, use arrow functions instead \
to be explicitly specified. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = function (s: string) { <br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = (s: string) => {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 47 ] = " \
 #47: Return type must be specified for lambdas explicitly<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
An explicit return type is mandatory for a lambda expression. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = (s: string) => { // return type is implicit<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return s.toLowerCase()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = (s: string): string => { // return type is explicit<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return s.toLowerCase()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 48 ] = " \
 #48: Shortcut syntax for lambdas is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support shortcut syntax for lambdas. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = (x: number) => { return x }<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = (x: number) => x<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: (x: number) => number =<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(x: number): number => { return x }<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b: (x: number) => number =<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(x: number): number => { return x }<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 50 ] = " \
 #50: Class literals are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support class literals. A new named class type must be \
introduced explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const Rectangle = class {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(height: number, width: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.heigth = height<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.width = width<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;heigth<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;width<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const rectangle = new Rectangle(0.0, 0.0)<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Rectangle {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(height: number, width: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.heigth = height<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.width = width<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;heigth: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;width: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const rectangle = new Rectangle(0.0, 0.0)<br> \
<br> \
</code><br> \
";

cookBookMsg[ 51 ] = " \
 #51: Classes cannot be specified in <code>implements</code> clause<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not allow to specify a class in implements clause. Only interfaces may be specified. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo() {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C1 implements C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo() {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C1 implements C {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo() {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 52 ] = " \
 #52: Attempt to access an undefined property is a compile-time error<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports accessing only those class properties that are either declared \
in the class, or accessible via inheritance. Accessing any other properties is \
prohibited and causes compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let person = {name: \"Bob\", isEmployee: true}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let n = typ[\"name\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = typ[\"isEmployee\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let s = typ[\"office\"] // undefined<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
Use proper types to check property existence during compilation. \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(name: string, isEmployee: boolean) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.name = name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.isEmployee = isEmployee<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;isEmployee: boolean<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let person = new Person(\"Bob\", true)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let n = typ.name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = typ.isEmployee<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let s = typ.office // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 53 ] = " \
 #53: Only <code>as T</code> syntax is supported for type casts<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports <code>as</code> keyword as the only syntax for type casts. \
Incorrect cast causes a compile-time error or runtime <code>ClassCastException</code>. \
<code><type></code> syntax for type casts is not supported. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Shape {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Circle extends Shape {x: number = 5}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Square extends Shape {y: string = \"a\"}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function createShape(): Shape {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Circle()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c1 = <Circle> createShape()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c2 = createShape() as Circle<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// No report is provided during compilation<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// nor during runtime if cast is wrong:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c3 = createShape() as Square<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(c3.y) // undefined<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Shape {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Circle extends Shape {x: number = 5}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Square extends Shape {y: string = \"a\"}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function createShape(): Shape {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Circle()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c2 = createShape() as Circle<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// ClassCastException during runtime is thrown:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c3 = createShape() as Square<br> \
<br> \
</code><br> \
";

cookBookMsg[ 54 ] = " \
 #54: JSX expressions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Do not use JSX since no alternative is provided to rewrite it. \
 \
<br> \
";

cookBookMsg[ 55 ] = " \
 #55: Unary operators <code>+</code>, <code>-</code> and <code>~</code> work only on numbers<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS allows unary operators to work on numeric types only. A compile-time \
error occurs if these operators are applied to a non-numeric type. Unlike in \
TypeScript, implicit casting of strings in this context is not supported and must \
be done explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = +5   // 5 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = +\"5\" // 5 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = -5   // -5 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = -\"5\" // -5 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = ~5   // -6 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = ~\"5\" // -6 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = +\"string\" // NaN as number<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = +5   // 5 as int<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = +\"5\" // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = -5   // -5 as int<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = -\"5\" // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = ~5   // -6 as int<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = ~\"5\" // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = +\"string\" // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 56 ] = " \
 #56: Unary <code>+</code> cannot be used for casting to <code>number</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support casting from any type to a numeric type \
by using the unary <code>+</code> operator, which can be applied only to \
numeric types. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnTen(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return \"-10\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnString(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return \"string\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = +returnTen()    // -10 as number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = +returnString() // NaN<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnTen(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return \"-10\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnString(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return \"string\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = +returnTen()    // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = +returnString() // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 57 ] = " \
 #57: <code>!</code> operator works only on values of the boolean type<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports using <code>!</code> operator only for values of the boolean type. \
Explicit cast from some type to the boolean (or Boolean) is mandatory. \
Implicit casts are prohibited and cause compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = !true      // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = !\"true\"    // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = !\"rnd_str\" // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = !\"false\"   // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = !5         // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = !0         // true<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = !true      // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = !\"true\"    // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = !\"false\"   // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = !\"rnd_str\" // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = !5         // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = !0         // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 59 ] = " \
 #59: <code>delete</code> operator is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS assumes that object layout is known at compile time and cannot be  \
changed at runtime. Thus the operation of deleting a property makes no sense. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x?: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y?: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;delete p.y<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// To mimic the original semantics, you may declare a nullable type<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// and assign null to mark value absence:<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number | null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number | null<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;p.y = null<br> \
<br> \
</code><br> \
";

cookBookMsg[ 60 ] = " \
 #60: <code>typeof</code> operator is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>typeof</code> operator and requires explicit typing. \
Use <code>instanceof</code> as a work-around where applicable. Type can be inferred \
from the initalizer, but the initial value can be not a default one. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(typeof 5) // \"number\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(typeof \"string\") // \"string\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let s = \"hello\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let n: typeof s // n type is string, n == \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = typeof s == \"string\" // true<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let s = \"hello\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let n = s<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = s instanceof string // true<br> \
<br> \
</code><br> \
";

cookBookMsg[ 61 ] = " \
 #61: Binary operators <code>*</code>, <code>/</code>, <code>%</code>, <code>-</code>, <code><<</code>, <code>>></code>, <code>>>></code>, <code>&</code>, <code>^</code> and <code>|</code> work only on numeric types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS allows applying binary operators <code>*</code>, <code>/</code>, <code>%</code>, <code>-</code>, <code><<</code>, \
<code>>></code>, <code>>>></code>, <code>&</code>, <code>^</code> and <code>|</code> only to values of numeric types. \
Implicit casts from other types to numeric types are prohibited and cause \
compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = (5 & 5)     // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = (5.5 & 5.5) // 5, not 5.5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = (5 | 5)     // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = (5.5 | 5.5) // 5, not 5.5<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Direction {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Up = -1,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Down<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = Direction.Up >> 1 // -1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = Direction.Up >>> 1 // 2147483647<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = (\"10\" as any) << 1  // 20<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let h = (\"str\" as any) << 1 // 0<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let i = 10 * 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let j = 10 / 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let k = 10 % 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let l = 10 - 5<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = (5 & 5)     // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = (5.5 & 5.5) // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = (5 | 5)     // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = (5.5 | 5.5) // Compile-time error<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Direction {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Up, // TBD: explicit start value<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Down<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = Direction.Up >> 1  // 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = Direction.Up >>> 1 // 0<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let i = 10 * 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let j = 10 / 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let k = 10 % 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let l = 10 - 5<br> \
<br> \
</code><br> \
";

cookBookMsg[ 62 ] = " \
 #62: Binary operators <code><<</code>, <code>>></code>, <code>>>></code>, <code>&</code>, <code>^</code> and <code>|</code> work only on integral numeric types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS expects an explicit cast to an integral type for logical binary \
operations. Implicit casts are prohibited and cause compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = (5.5 & 5.5) // 5, not 5.5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = (5.5 | 5.5) // 5, not 5.5<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = (\"10\" as any) << 1  // 20<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let h = (\"str\" as any) << 1 // 0<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = (5.5 & 5.5) // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = (5.5 | 5.5) // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 63 ] = " \
 #63: Binary <code>+</code> operator supports implicit casts only for numbers and strings<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports implicit casts for <code>+</code> only for strings and numbers. \
Elsewhere, any form of an explicit cast to string is required. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum E { E1, E2 }<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = 10 + 32   // 42<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = E.E1 + 10 // 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 10 + \"5\"  // \"105\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"5\" + E.E2 // \"51\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"Hello, \" + \"world!\" // \"Hello, world!\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = \"string\" + true // \"stringtrue\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = (new Object()) + \"string\" // \"[object Object]string\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum E { E1, E2 }<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = 10 + 32   // 42<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = E.E1 + 10 // 10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 10 + \"5\"  // \"105\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"5\" + E.E2 // \"51\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"Hello, \" + \"world!\" // \"Hello, world!\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let f = \"string\" + true // \"stringtrue\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let g = (new Object()).toString() + \"string\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 64 ] = " \
 #64: Binary <code>+</code> operator requires explicit casts for non-numbers and non-strings<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports implicit casts for <code>+</code> only for strings and numbers. \
Elsewhere, any form of an explicit cast to string is required. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// \"[object Object][object Object]\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let o = ({x: 5} as any) + {y: 6}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let o = (new Object()).toString() + new Int(5) // \"5\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 66 ] = " \
 #66: <code>in</code> operator is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the <code>in</code> operator. However, this operator makes \
little sense since the object layout is known at compile time and cannot \
be modified at runtime. Use <code>instanceof</code> as a work-around if you still need \
to check whether certain class members exist. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = new Person()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = \"name\" in p // true<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = new Person()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = p instanceof Person // true, and \"name\" is guaranteed to be present<br> \
<br> \
</code><br> \
";

cookBookMsg[ 67 ] = " \
 #67: Operators <code>&&</code> and <code>||</code> work on values of the boolean type only<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports using <code>&&</code> and <code>||</code> operators only for the values of the \
boolean type. Explicit cast from some type to the boolean (or Boolean) is \
mandatory. Implicit casts are prohibited and cause compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = true && false // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 5 || 0        // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 5 && 0        // 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"\" && 5       // \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"\" || \"abcd\"  // \"abcd\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = true && false // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 5 || 0        // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 5 && 0        // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"\" && 5       // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"\" || \"abcd\"  // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 68 ] = " \
 #68: Using of <code>&&</code> and <code>||</code> on non-boolean types is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the usage of <code>&&</code> and <code>||</code> operators only for the values \
of the boolean type. Explicit cast from some type to the boolean (or Boolean) \
is mandatory. Implicit casts are prohibited and cause compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = true && false // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 5 || 0        // 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 5 && 0        // 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"\" && 5       // \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"\" || \"abcd\"  // \"abcd\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = true && false // false<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 5 || 0        // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = 5 && 0        // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = \"\" && 5       // Compile-time error<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let e = \"\" || \"abcd\"  // Compile-time error<br> \
<br> \
</code><br> \
";

cookBookMsg[ 69 ] = " \
 #69: Destructuring assignment is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support destructuring assignment. Other idioms (e.g., \
using a temporary variable, where applicable) can be used for replacement. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let [one, two] = [1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;[one, two] = [two, one]<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let head, tail<br> \
&nbsp;&nbsp;&nbsp;&nbsp;[head, ...tail] = [1, 2, 3, 4]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let arr: number[] = [1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let one = arr[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let two = arr[1]<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let tmp = one<br> \
&nbsp;&nbsp;&nbsp;&nbsp;one = two<br> \
&nbsp;&nbsp;&nbsp;&nbsp;two = tmp<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let data: Number[] = [1,2,3,4]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let head = data[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let tail = new Number[data.length - 1]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 1; i < data.length; ++i) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;tail[i-1] = data[i]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 71 ] = " \
 #71: The comma operator <code>,</code> is supported only in <code>for</code> loops<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the comma operator <code>,</code> only in <code>for</code> loops. Otherwise, \
it is useless as it makes the execution order harder to understand. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 0, j = 0; i < 10; ++i, j += 2) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(i, j)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = (++x, x++) // 1<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 0, j = 0; i < 10; ++i, j += 2) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(i, j)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Use explicit execution order instead of the comma operator:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;++x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;x = x++<br> \
<br> \
</code><br> \
";

cookBookMsg[ 73 ] = " \
 #74: Destructuring variable declarations are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support destructuring variable declarations. This is a dynamic \
feature relying on structural compatibility. In addition, names in destructuring \
declarations must be equal to properties within destructured classes. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnZeroPoint(): Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let {x, y} = returnZeroPoint()<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 0.0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function returnZeroPoint(): Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Create an intermediate object and work with it field by field<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// without name restrictions:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let zp = returnZeroPoint()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = zp.x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = zp.y<br> \
<br> \
</code><br> \
";

cookBookMsg[ 76 ] = " \
 #76: Inference of implied types is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support inference of implied types. Use explicit \
type notation instead. Use <code>Object[]</code> if you need containers that hold \
data of mixed types. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let [a, b, c] = [1, \"hello\", true]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = \"hello\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = true<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let arr: Object[] = [1, \"hello\", true]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a1 = arr[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b1 = arr[1]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c1 = arr[2]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 78 ] = " \
 #78: Implicit casts to the boolean are not supported in <code>if</code>, <code>do</code> and <code>while</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports only values of the boolean type in <code>if</code>, <code>do</code> and <code>while</code> \
statements. Implicit casts from other types to the boolean are prohibited and \
cause compile-time errors. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (true) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {} while (false)<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = new Boolean(true)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (a) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (a)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (a) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 42<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (b) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (b)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (b) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = \"str\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (c) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (c)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (c) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = new Object()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (d) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (d)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (d) {break}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (true) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {} while (false)<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = new Boolean(true)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (a) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (a)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (a) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 42<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (b != 0) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (b != 0)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (b != 0) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let c = \"str\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (c.length != 0) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (c.length != 0)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (c.length != 0) {break}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let d = new Object()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (d != null) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;do {break} while (d != null)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;while (d != null) {break}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 79 ] = " \
 #79: Type annotation in catch clause is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
In TypeScript catch clause variable type annotation must be <code>any</code> or <code>unknown</code> if specified.  \
As ArkTS does not support these types, a type annotation should be omitted. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;try { <br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// some code<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;catch (a: unknown) {}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;try { <br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// some code<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;catch (a) {}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 80 ] = " \
 #80: <code>for .. in</code> is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the iteration over object contents by the \
<code>for .. in</code> loop. For objects, iteration over properties at runtime is \
considered redundant because object layout is known at compile time and cannot \
change at runtime. For arrays, you can iterate with the regular <code>for</code> loop. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: number[] = [1.0, 2.0, 3.0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i in a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(a[i])<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: number[] = [1.0, 2.0, 3.0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 0; i < a.length; ++i) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(a[i])<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 81 ] = " \
 #81: Iterable interfaces are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the <code>Symbol</code> API, <code>Symbol.iterator</code> and \
eventually iterable interfaces. Use arrays and library-level containers to \
iterate over data. \
 \
<br> \
";

cookBookMsg[ 82 ] = " \
 #82: <code>for-of</code> is supported only for arrays<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the iteration over arrays by the <code>for .. of</code> loop, \
but does not support the iteration of objects content. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: string[] = [\"a\", \"b\", \"c\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let s of a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a: string[] = [\"a\", \"b\", \"c\"]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let s of a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(s)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 83 ] = " \
 #83: Mapped type expression is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support mapped types. Use other language idioms and regular classes \
to achieve the same behaviour. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;type OptionsFlags<Type> = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Property in keyof Type]: boolean;<br> \
&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 84 ] = " \
 #84: <code>with</code> statement is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the <code>with</code> statement. Use other language idioms \
(including fully qualified names of functions) to achieve the same behaviour. \
 \
<br> \
";

cookBookMsg[ 85 ] = " \
 #85: Values computed at runtime are not supported in <code>case</code> statements<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports <code>case</code> statements that contain only compile-time values. \
Use <code>if</code> statements as an alternative. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = 3<br> \
&nbsp;&nbsp;&nbsp;&nbsp;switch (x) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case 1:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(1)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case 2:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case y:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(y)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;default:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"other\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;switch (x) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case 1:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(1)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case 2:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case 3:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(3)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;break<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;default:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"other\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 86 ] = " \
 #86: <code>switch</code> statements cannot accept values of arbitrary types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports the values of the types <code>char</code>, <code>byte</code>, <code>short</code>, <code>int</code>, \
<code>long</code>, <code>Char</code>, <code>Byte</code>, <code>Short</code>, <code>Int</code>, <code>Long</code>, <code>String</code> or \
<code>enum</code> in <code>switch</code> statements. Use <code>if</code> statements in other cases. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = new Point()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;switch (a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;case null: break;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;default: console.log(\"not null\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = new Point()<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (a != null) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"not null\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 87 ] = " \
 #87: <code>throw</code> statements cannot accept values of arbitrary types<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS supports throwing only objects of the class <code>Error</code> or any \
derived class. Throwing an arbitrary type (i.e., a <code>number</code> or <code>string</code>) \
is prohibited. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;throw 4<br> \
&nbsp;&nbsp;&nbsp;&nbsp;throw \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;throw new Error()<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;throw new Error()<br> \
<br> \
</code><br> \
";

cookBookMsg[ 88 ] = " \
 #88: Each overloaded function should have its body<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the TypeScript style of overloading signatures with one \
function body. Define each overloading function with its own body instead of \
one body for a list of signatures. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function add(x: number, y: number): number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function add(x: string, y: string): string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function add(x: any, y: any): any {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x + y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(add(2, 3)) // returns 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(add(\"hello\", \"world\")) // returns \"helloworld\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function add(x: number, y: number): number {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x + y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function add(x: string, y: string): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x + y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(add(2, 3)) // returns 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(add(\"hello\", \"world\")) // returns \"helloworld\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 89 ] = " \
 #89: Each overloaded function with optional parameters should have its body<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the TypeScript style of overloading signatures with one \
function body. Write a separate body for each overloaded signature instead of \
an optional parameter like `value?` for a single body in TypeScript. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(name: string): number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(name: string, value: string): Accessor<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(name: any, value?: string): any {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// one body here<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(name: string): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(name: string, value: string): Accessor {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Accessor()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 90 ] = " \
 #90: Function must have explicit return type<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS requires all functions to have explicit return types. For corner cases, \
use `Object` when it is difficult to determine the return type. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(x: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (x <= 0) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return g(x)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function g(x: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return f(x - 1)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doOperation(x: number, y: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x + y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(f(10))<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(doOperation(2, 3))<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function f(x: number): Object {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (x <= 0) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return g(x)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function g(x: number): Object {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return f(x - 1)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doOperation(x: number, y: number): Object {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let z = x + y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return z<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(f(-10) as number) // returns -10<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(doOperation(2, 3)) // returns 5<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 91 ] = " \
 #91: Destructuring parameter declarations are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS requires that parameters must be passed directly to the function, and \
local names must be assigned manually. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function drawText({ text = \"\", location: [x, y] = [0, 0], bold = false }) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(text)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(y)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(bold)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;drawText({ text: \"Hello, world!\", location: [100, 50], bold: true })<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function drawText(text: String, location: number[], bold: boolean) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let x = location[0]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let y = location[1]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(text)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(x)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(y)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(bold)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;drawText(\"Hello, world!\", [100, 50], true)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 92 ] = " \
 #92: Nested functions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support nested functions. Use lambdas instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function addNum(a: number, b: number): void {<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// nested function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;function logToConsole(message: String): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(message)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let result = a + b<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Invoking the nested function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;logToConsole(\"result is \" + result)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function addNum(a: number, b: number): void {<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// Use lambda instead of a nested function:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let logToConsole: (message: String): void = (message: String): void => {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.println(message)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let result = a + b<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;logToConsole(\"result is \" + result)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 93 ] = " \
 #93: Using <code>this</code> inside stand-alone functions is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the usage of <code>this</code> inside stand-alone functions. \
<code>this</code> can be used in methods only. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(i: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.count = i<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;count: number = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;m = foo<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = new A()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(a.count) // prints \"1\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;a.m(2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(a.count) // prints \"2\"<br> \
<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;count: number = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;m(i: number): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.count = i<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let a = new A()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(a.count)  // prints \"1\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;a.m(2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(a.count)  // prints \"2\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 94 ] = " \
 #94: Generator functions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support generator functions. \
Use the <code>async</code> / <code>await</code> mechanism for multitasking. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function* counter(start: number, end: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;for (let i = start; i <= end; i++) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;yield i<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let num of counter(1, 5)) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(num)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 1; i <= 5; ++i) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(i)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 95 ] = " \
 #95: Asynchronous functions are partially supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS partially supports asynchronous functions. \
Using the <code>launch</code> mechanism (ArkTS extension to TypeScript) \
is recommended for multitasking. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;async function sum(numbers: number[]): Promise<number> {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let sum = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;for (let num of numbers) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sum += await num<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return sum<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const result = await sum(5, 10)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;...<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function sum(numbers: number[]): number {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let sum = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;for (let i = 0; i < numbers.length; ++i) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;sum += numbers[i]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return sum<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const result = launch sum(5, 10)  // `result` will be of type `Promise<number>`<br> \
&nbsp;&nbsp;&nbsp;&nbsp;...<br> \
<br> \
NOT recommended:<br> \
<br> \
</code><br> \
";

cookBookMsg[ 96 ] = " \
 #96: Type guarding is supported with <code>instanceof</code> and <code>as</code><br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the <code>is</code> operator, which must be replaced by the \
<code>instanceof</code> operator. Note that the fields of an object must be cast to the \
appropriate type with the <code>as</code> operator before use. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Foo {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;common: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Bar {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bar: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;common: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function isFoo(arg: any): arg is Foo {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return arg.foo !== undefined<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doStuff(arg: Foo | Bar) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (isFoo(arg)) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.foo)    // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.bar)    // Error!<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.foo)    // Error!<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.bar)    // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;doStuff({ foo: 123, common: '123' })<br> \
&nbsp;&nbsp;&nbsp;&nbsp;doStuff({ bar: 123, common: '123' })<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Foo {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;common: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Bar {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bar: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;common: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function isFoo(arg: Object): boolean {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return arg instanceof Foo<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function doStuff(arg: Object): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (isFoo(arg)) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let fooArg = arg as Foo<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(fooArg.foo)     // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.bar)        // Error!<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let barArg = arg as Bar<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(arg.foo)        // Error!<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(barArg.bar)     // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;doStuff(new Foo())<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;doStuff(new Bar())<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 97 ] = " \
 #97: `keyof` operator is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS has no `keyof` operator because the object layout is defined \
at compile time and cannot be changed at runtime. Object fields can only be \
accessed directly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type PointKeys = keyof Point  // The type of PointKeys is \"x\" | \"y\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function getPropertyValue(obj: Point, key: PointKeys) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return obj[key]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let obj = new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(getPropertyValue(obj, \"x\"))  // prints \"1\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(getPropertyValue(obj, \"y\"))  // prints \"2\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function getPropertyValue(obj: Point, key: string): number {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (key.equals(\"x\")) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return obj.x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (key.equals(\"y\")) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return obj.y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;throw new Error()  // No such property<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let obj = new Point()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(getPropertyValue(obj, \"x\"))  // prints \"1\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(getPropertyValue(obj, \"y\"))  // prints \"2\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 98 ] = " \
 #98: Spreading an array into function arguments is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the spread operator. \
\"Unpack\" data from an array to a callee manually. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(x, y, z) {}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let args = [0, 1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;foo(...args)<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function foo(x: number, y: number, z: number): void {}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let args: number[] = [0, 1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo(args[0], args[1], args[2])<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 99 ] = " \
 #99: Spread operator is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the spread operator. \
\"Unpack\" data from arrays indices manually where necessary. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let list = [1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;list = [...list, 3, 4]<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let list: number[] = [1, 2]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;list = [list[0], list[1], 3, 4]<br> \
<br> \
</code><br> \
";

cookBookMsg[ 100 ] = " \
 #100: Spreading an object is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the spread operator. \
\"Unpack\" data from an object to a callee manually, field by field. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const point2d = {x: 1, y: 2}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const point3d = {...point2d, z: 3}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point2D {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(x: number, y: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.x = x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.y = y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point3D {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;z: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(x: number, y: number, z: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.x = x<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.y = y<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.z = z<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const point2d = new Point2D(1, 2)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const point3d = new Point3D(point2d.x, point2d.y, 3)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 103 ] = " \
 #103: Declaration merging is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support merging declratations. All definitions of classes, \
interfaces and so on must be kept compact in the code base. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: any): Element<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string): HTMLElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: number): HTMLDivElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: boolean): HTMLSpanElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string, value: number): HTMLCanvasElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Document {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: number): HTMLDivElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: boolean): HTMLSpanElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string, value: number): HTMLCanvasElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: string): HTMLElement<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;createElement(tagName: Object): Element<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 104 ] = " \
 #104: Interfaces cannot extend classes<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support interfaces that extend classes. Interfaces can extend \
only interfaces. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Control {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;state: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface SelectableControl extends Control {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;select(): void<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface Control {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;state: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;interface SelectableControl extends Control {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;select(): void<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 105 ] = " \
 #105: Property-based runtime type checks are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS requires that object layout is determined in compile-time and cannot \
be changed at runtime. There for no runtime property-based checks are supported. \
If you need to do a type cast, use <code>as</code> operator and use desired properties \
and methods. If some property doesn't exist then an attempt to reference it \
will result in a compile-time error. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo() {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bar() {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function getSomeObject() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new A()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let obj: any = getSomeObject()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (obj && obj.foo && obj.bar) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"Yes\")  // prints \"Yes\" in this example<br> \
&nbsp;&nbsp;&nbsp;&nbsp;} else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"No\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;foo(): void {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bar(): void {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function getSomeObject(): A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new A()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let tmp: Object = getSomeObject()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let obj: A = tmp as A<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;obj.foo()       // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;obj.bar()       // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;obj.some_foo()  // Compile-time error: Method some_foo does not exist on this type<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 106 ] = " \
 #106: Constructor function type is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the usage of the constructor function type. \
Use lambdas instead, as they can be generalized to several types of objects. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;type PersonConstructor = new (name: string, age: number) => Person<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function createPerson(Ctor: PersonConstructor, name: string, age: number): Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Ctor(name, age)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const person = createPerson(Person, 'John', 30)<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let PersonConstructor: (name: string, age: number): Person = (name: string, age: number): Person => {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return new Person(name, age)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function createPerson(Ctor: (name: string, age: number): Person, name: string, age: number): Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return PersonConstructor(name, age)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const person = createPerson(PersonConstructor, \"John\", 30)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 107 ] = " \
 #107: Constructor declarations<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support optional parameters in constructors. \
Constructors are not inherited from a superclass to a subclass. Use overloading \
constructors instead of constructors with optional parameters: \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Foo {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(bar: string = 'default', baz?: number) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Foo {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(bar: string) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(bar: string, baz: number) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 108 ] = " \
 #108: Overloaded constructors with shared body are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support sharing a body between function overloads. \
The shared body feature for <code>constructor</code> is not supported, either. \
Overload constructor with a separate body for each signature. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(name: string, age?: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.name = name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (age) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.age = age<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;} else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.age = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(name: string, age: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.name = name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.age = age<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(name: string) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.name = name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.age = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 109 ] = " \
 #109: Dynamic property declaration is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support dynamic property declaration. All object properties must \
be declared immediately in the class. While it can be replaced with an array \
of objects, it is still better to adhere to the static language paradigm and \
declare fields, their names and types explicitly. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string = \"\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number = 0<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[key: string]: string | number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const person: Person = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: \"John\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: 30,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;email: \"john@example.com\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;phone: 1234567890,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Person {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;age: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;email: string<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;phone: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(name: string, age: number, email: string, phone: number) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.name = name<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.age = age<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.email = email<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this.phone = phone<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const person: Person = new Person(\"John\", 30, \"john@example.com\", 1234567890)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 111 ] = " \
 #111: Explicit values for enumeration constants are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
Currently, ArkTS does not support assigning explicit values for <code>enums</code>. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum E {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;A,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;B,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C = 10,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;D<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum E {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;A,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;B,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C = 10,  // Compile-time error: assigning out of order values for enums is not supported<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;D<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum E_fixed {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;A,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;B,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;C,   // OK<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;D<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 112 ] = " \
";

cookBookMsg[ 113 ] = " \
 #113: <code>enum</code> declaration merging is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support merging declratations for <code>enum</code>. \
The declaration of each <code>enum</code> must be kept compact in the code base. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Color {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RED,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;GREEN<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Color {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;YELLOW<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Color {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;BLACK,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;BLUE<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;enum Color {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RED,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;GREEN,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;YELLOW,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;BLACK,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;BLUE<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 114 ] = " \
 #114: Namespaces cannot be used as objects<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support the usage of namespaces as objects. \
Classes or modules can be interpreted as analogues of namespaces. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;namespace MyNamespace {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export let x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let m = MyNamespace<br> \
&nbsp;&nbsp;&nbsp;&nbsp;m.x = 2<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;namespace MyNamespace {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export let x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;MyNamespace.x = 2<br> \
<br> \
</code><br> \
";

cookBookMsg[ 115 ] = " \
 #115: Scripts and modules<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
In general, scripts and modules in ArkTS are very close to TypeScript. \
Differences are described in separate recipes. \
 \
<br> \
";

cookBookMsg[ 116 ] = " \
 #116: Non-declaration statements in namespaces are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support statements in namespaces. Use a function to exectute statements. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;namespace A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export let x: number<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
Initialization function should be called to execute statements. \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;namespace A {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export let x: number<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export function init() {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;A.init()<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 117 ] = " \
 #117: Statement as top-level element<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support statements as top-level elements. Statements must be \
placed in a block <code>{}</code>. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let a = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let b = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;if (b == a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"a EQ b\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;} else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"a NEQ b\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// A block can be a top-level element,<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// put statements inside one or several blocks:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;{<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let a = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;let b = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;{<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if (b == a) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"a EQ b\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;} else {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log(\"a NEQ b\")<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
<br> \
</code><br> \
";

cookBookMsg[ 118 ] = " \
 #118: Special import type declarations are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not have a special notation for importing types. \
Use ordinary import instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Re-using the same import<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { APIResponseType } from \"./api\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Explicitly use import type<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import type { APIResponseType } from \"./api\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { APIResponseType } from \"./api\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 119 ] = " \
 #119: Importing a module for side-effects only is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support global variables like <code>window</code> to avoid \
side-effects during module importing. All variables marked as export can be \
accessed through the <code>*</code> syntax. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// === module at \"path/to/module.ts\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export const EXAMPLE_VALUE = 42<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Set a global variable<br> \
&nbsp;&nbsp;&nbsp;&nbsp;window.MY_GLOBAL_VAR = \"Hello, world!\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// ==== using this module:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import \"path/to/module\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import * from \"path/to/module\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 120 ] = " \
 #120: <code>import default as ...</code> is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>import default as ...</code> syntax. \
Use explicit <code>import ... from ...</code> instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { default as d } from \"mod\"<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import d from \"mod\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 121 ] = " \
 #121: <code>require</code> is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support importing via <code>require</code>. Use <code>import</code> instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import m = require(\"mod\")<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import * as m from \"mod\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 122 ] = " \
 #122: <code>export default</code> is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>export default</code>. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// file1.ts<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export default class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// file2.ts<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Can write just `MyClass` instead of `{ MyClass }` in case of default export<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import MyClass from './file1'<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Use explicit name in import<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { MyClass } from \"./module1\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 123 ] = " \
 #123: Renaming in export declarations is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support renaming in export declarations. Similar effect \
can be achieved through setting an alias for the exported entity. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// file1.ts<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export { MyClass as RenamedClass }<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// file2.ts<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { RenamedClass } from \"./file1\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const myObject = new RenamedClass()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export RenamedClass = MyClass<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import RenamedClass from \"./module1\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function main(): void {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const myObject = new RenamedClass()<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 124 ] = " \
 #124: Export list declaration is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support syntax of export list declarations. All exported \
entities must be explicitly annotated with the <code>export</code> keyword. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export { x }<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export { x } from \"mod\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export { x, y as b, z as c }<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = 1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class MyClass {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export let y = x, z: number = 2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export RenamedClass = MyClass<br> \
<br> \
</code><br> \
";

cookBookMsg[ 125 ] = " \
 #125: Re-exporting is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support re-exporting. All desired entities must be \
imported explicitly from the modules that export them. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export { MyClass } from \"module1\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// consumer module<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { MyClass } from \"module2\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const myInstance = new MyClass()<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export class MyClass {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// some stuff<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// consumer module<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import MyClass from \"module1\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import * from \"module2\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const myInstance = new MyClass()<br> \
<br> \
</code><br> \
";

cookBookMsg[ 126 ] = " \
 #126: <code>export = ...</code> assignment is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not support <code>export = ...</code> syntax. \
Use regular <code>export</code> / <code>import</code> instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export = Point<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(x: number, y: number) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static origin = new Point(0, 0)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import Pt = require(\"module1\")<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = Pt.origin<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export class Point {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;constructor(x: number, y: number) {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;static origin = new Point(0, 0)<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// module2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import * as Pt from \"module1\"<br> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let p = Pt.origin<br> \
<br> \
</code><br> \
";

cookBookMsg[ 127 ] = " \
 #127: Special export type declarations are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
 \
ArkTS does not have a special notation for exporting types. \
Use ordinary export instead. \
 \
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class C {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export type { C }<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export class C {}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;<br> \
<br> \
</code><br> \
";

cookBookMsg[ 128 ] = " \
#128: Shorthand ambient module declaration is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
Not supported because ArkTS has its own mechanism of interop with JavaScript. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;declare module \"hot-new-module\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 129 ] = " \
#129: Wildcards in module names are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
Not supported because in ArkTS import is a compile-time, not a run-time feature. \
Additionally, \"declare module\" is not supported (#128) \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;declare module \"*!text\" {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const content: string;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;export default content;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 130 ] = " \
#130: UMD module definitions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
Not supported because in ArkTS import is a compile-time, not a run-time feature. \
Additionally, there is no concept of a \"script\" in ArkTS. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// math-lib.d.ts<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export const isPrime(x: number): boolean;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export as namespace mathLib;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// in script<br> \
&nbsp;&nbsp;&nbsp;&nbsp;mathLib.isPrime(2);<br> \
<br> \
</code><br> \
";

cookBookMsg[ 131 ] = " \
#131: .js extension is not allowed in module identifiers<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
Not supported because ArkTS has its own mechanism of interop with JavaScript. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import d from \"./moduleA.js\"<br> \
<br> \
</code><br> \
";

cookBookMsg[ 132 ] = " Recipe #132 TBD\
";


cookBookMsg[ 133 ] = " \
#133: Dynamic import expressions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
ArkTS does not support dynamic import expressions because in ArkTS import is a compile-time, \
not a runtime feature. Use regular import syntax instead. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const zipUtil = await import(\"create-zip-file\");<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { zipUtil } from \"create-zip-file\";<br> \
<br> \
</code><br> \
";

cookBookMsg[ 134 ] = " Recipe #134 TBD\
";

cookBookMsg[ 135 ] = " Recipe #135 TBD\
";

cookBookMsg[ 137 ] = " \
#137: \"globalThis\" is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
ArkTS does not support both global scope and \"globalThis\" because untyped objects with \
dynamically changed layout are not supported. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// in a global file:<br> \
&nbsp;&nbsp;&nbsp;&nbsp;var abc = 100;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Refers to abc from above<br> \
&nbsp;&nbsp;&nbsp;&nbsp;globalThis.abc = 200;<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// file1<br> \
&nbsp;&nbsp;&nbsp;&nbsp;export let abc: number = 100;<br> \
&nbsp;&nbsp;&nbsp;&nbsp; // file2<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import * as M from \"file1\";<br> \
&nbsp;&nbsp;&nbsp;&nbsp;M.abc = 200;<br> \
<br> \
</code><br> \
";

cookBookMsg[ 139 ] = " \
#137: Declaring properties on functions is not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
ArkTS does not support declaring properties on functions because there is no support for objects with \
dynamically changing layout. Function objects follow this rule and their layout cannot be changed at \
runtime. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Image {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function readImage(path: string, callback: (err: any, image: Image) => void) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;readImage.sync = (path: string) => {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;const contents = fs.readFileSync(path);<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return decodeImageSync(contents);<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Image {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// ...<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function readImage(path: string, callback: (err: any, image: Image) => void) {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// async implenentation<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;function readImageSync(path: string): Image {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;// sync implementation<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
<br> \
</code><br> \
";

cookBookMsg[ 140 ] = " \
#140: Function.apply, Function.bind, Function.call are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
These methods are needed in standard library to explicitly set \"this\" parameter for the called function. \
In ArkTS, semantics of \"this\" is restricted to the conventional OOP style, and usage of \"this\" in \
standalone functions is prohibited. Thus, these functions are excessive. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;const person = {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;firstName: \"aa\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;lastName: \"bb\",<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;fullName: function(): string {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return this.firstName + \" \" + this.lastName;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// This will log \"Jane Doe\"<br> \
&nbsp;&nbsp;&nbsp;&nbsp;console.log(person.fullName.apply({firstName: \"Jane\", lastName: \"Doe\"}));<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
<code> \
<br> \
";

cookBookMsg[ 142 ] = " \
#142: \"as const\" assertions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
ArkTS does not support \"as const\" assertions because in the standard TypeScript \"as const\" annotates \
literals with corresponding literal types, and ArkTS does not support literal types. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type 'hello'<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x = \"hello\" as const;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type 'readonly [10, 20]<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y = [10, 20] as const;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type '{ readonly test: \"hello\" }'<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let z = { text: \"hello\" } as const;<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
 <code> \
 <br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type 'string'<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let x: string = \"hello\";<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type 'number[]'<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let y: number[] = [10, 20];<br> \
&nbsp;&nbsp;&nbsp;&nbsp;class Label {<br> \
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;text: string;<br> \
&nbsp;&nbsp;&nbsp;&nbsp;}<br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Type 'Label'<br> \
&nbsp;&nbsp;&nbsp;&nbsp;let z: Label = { text: \"hello\" };<br> \
<br> \
</code><br> \
";

cookBookMsg[ 143 ] = " \
#143: Import assertions are not supported<br> \
<hr style=\"height:3px;\"><b>Rule</b><br> \
\
ArkTS does not support import assertions because in ArkTS, import is a compile-time, not a runtime feature. \
So asserting correctness of imported APIs in runtime does not make sense for the statically typed language. \
Use ordinary import syntax instead. \
\
<br> \
<hr style=\"height:3px;\"><b>TypeScript</b><br> \
\
<code> \
<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { obj } from \"something.json\" assert { type: json };<br> \
<br> \
</code><br> \
<hr style=\"height:3px;\"><b>ArkTS</b><br> \
 \
 <code> \
 <br> \
&nbsp;&nbsp;&nbsp;&nbsp;// Correctness of importing will be checked at compile-time<br> \
&nbsp;&nbsp;&nbsp;&nbsp;import { something } from \"module\";<br> \
<br> \
</code><br> \
";

cookBookTag[ 1 ] = "#1: Objects with property names that are not identifiers are not supported";
cookBookTag[ 2 ] = "#2: 'Symbol()' API is not supported";
cookBookTag[ 3 ] = "#3: Private '#' identifiers are not supported";
cookBookTag[ 4 ] = "#4: Use unique names for types, namespaces, etc.";
cookBookTag[ 5 ] = "#5: Use 'let' instead of 'var'";
cookBookTag[ 6 ] = "";
cookBookTag[ 7 ] = "";
cookBookTag[ 8 ] = "#8: Use explicit types instead of 'any', 'undefined', 'unknown'";
cookBookTag[ 9 ] = "#9: You can extend your TypeScript code with more numeric types";
cookBookTag[ 10 ] = "#10: Use 'long' instead of 'bigint'";
cookBookTag[ 11 ] = "#11: Use 'enum' instead of string literal types";
cookBookTag[ 12 ] = "#12: Use 'T[]' instead of 'Array<T>' to declare arrays";
cookBookTag[ 13 ] = "#13: Use 'Object[]' instead of tuples";
cookBookTag[ 14 ] = "#14: Use 'class' instead of a type with call signature";
cookBookTag[ 15 ] = "#15: Use 'class' instead of a type with constructor signature";
cookBookTag[ 16 ] = "#16: Only one static block is supported";
cookBookTag[ 17 ] = "#17: Indexed signatures are not supported";
cookBookTag[ 18 ] = "#18: Use 'Object' instead of union types";
cookBookTag[ 19 ] = "#19: Use inheritance instead of intersection types";
cookBookTag[ 20 ] = "#20: Default values for type parameters in generics are not supported";
cookBookTag[ 21 ] = "#21: Returning 'this' type is not supported";
cookBookTag[ 22 ] = "";
cookBookTag[ 23 ] = "#22: Conditional types are not supported";
cookBookTag[ 24 ] = "#24: Optional arguments are not supported";
cookBookTag[ 25 ] = "#25: Declaring fields in 'constructor' is not supported";
cookBookTag[ 26 ] = "#26: Specialized signatures are not supported";
cookBookTag[ 27 ] = "#27: Construct signatures not supported in interfaces";
cookBookTag[ 28 ] = "#28: Indexed access types are not supported";
cookBookTag[ 29 ] = "#29: Indexed access is not supported for fields";
cookBookTag[ 30 ] = "#30: Structural identity is not supported";
cookBookTag[ 31 ] = "#31: Structural typing is not supported for subtyping / supertyping";
cookBookTag[ 32 ] = "#32: Structural typing is not supported for assignability checks";
cookBookTag[ 33 ] = "#33: Optional properties are not supported";
cookBookTag[ 34 ] = "#34: Generic functions must be called with explicit type specialization";
cookBookTag[ 35 ] = "#35: Structural typing is not supported for type inference";
cookBookTag[ 36 ] = "#36: Type widening is not supported";
cookBookTag[ 37 ] = "#37: RegExp literals are not supported";
cookBookTag[ 38 ] = "#38: Object literal must correspond to explicitly declared class or interface";
cookBookTag[ 39 ] = "#39: Object literals must correspond to explicitly declared class or interface";
cookBookTag[ 40 ] = "#40: Object literals cannot be used as type declarations";
cookBookTag[ 41 ] = "";
cookBookTag[ 42 ] = "#42: Array literals must correspond to known array types";
cookBookTag[ 43 ] = "#43: Untyped array literals are not supported";
cookBookTag[ 44 ] = "#44: Template literals are not supported";
cookBookTag[ 45 ] = "#45: Lambdas require explicit type annotation for parameters";
cookBookTag[ 46 ] = "#46: Use arrow functions instead of function expressions";
cookBookTag[ 47 ] = "#47: Return type must be specified for lambdas explicitly";
cookBookTag[ 48 ] = "#48: Shortcut syntax for lambdas is not supported";
cookBookTag[ 49 ] = "";
cookBookTag[ 50 ] = "#50: Class literals are not supported";
cookBookTag[ 51 ] = "#51: Classes cannot be specified in 'implements' clause";
cookBookTag[ 52 ] = "#52: Attempt to access an undefined property is a compile-time error";
cookBookTag[ 53 ] = "#53: Only 'as T' syntax is supported for type casts";
cookBookTag[ 54 ] = "#54: JSX expressions are not supported";
cookBookTag[ 55 ] = "#55: Unary operators '+', '-' and '~' work only on numbers";
cookBookTag[ 56 ] = "#56: Unary '+' cannot be used for casting to 'number'";
cookBookTag[ 57 ] = "#57: '!' operator works only on values of the boolean type";
cookBookTag[ 58 ] = "";
cookBookTag[ 59 ] = "#59: 'delete' operator is not supported";
cookBookTag[ 60 ] = "#60: 'typeof' operator is not supported";
cookBookTag[ 61 ] = "#61: Binary operators '*', '/', '%', '-', '<<', '>>', '>>>', '&', '^' and '|' work only on numeric types";
cookBookTag[ 62 ] = "#62: Binary operators '<<', '>>', '>>>', '&', '^' and '|' work only on integral numeric types";
cookBookTag[ 63 ] = "#63: Binary '+' operator supports implicit casts only for numbers and strings";
cookBookTag[ 64 ] = "#64: Binary '+' operator requires explicit casts for non-numbers and non-strings";
cookBookTag[ 65 ] = "";
cookBookTag[ 66 ] = "#66: 'in' operator is not supported";
cookBookTag[ 67 ] = "#67: Operators '&&' and '||' work on values of the boolean type only";
cookBookTag[ 68 ] = "#68: Using of '&&' and '||' on non-boolean types is not supported";
cookBookTag[ 69 ] = "#69: Destructuring assignment is not supported";
cookBookTag[ 70 ] = "";
cookBookTag[ 71 ] = "#71: The comma operator ',' is supported only in 'for' loops";
cookBookTag[ 72 ] = "";
cookBookTag[ 73 ] = "#74: Destructuring variable declarations are not supported";
cookBookTag[ 74 ] = "";
cookBookTag[ 75 ] = "";
cookBookTag[ 76 ] = "#76: Inference of implied types is not supported";
cookBookTag[ 77 ] = "";
cookBookTag[ 78 ] = "#78: Implicit casts to the boolean are not supported in 'if', 'do' and 'while'";
cookBookTag[ 79 ] = "#79: Type annotation in catch clause is not supported";
cookBookTag[ 80 ] = "#80: 'for .. in' is not supported";
cookBookTag[ 81 ] = "#81: Iterable interfaces are not supported";
cookBookTag[ 82 ] = "#82: 'for-of' is supported only for arrays";
cookBookTag[ 83 ] = "#83: Mapped type expression is not supported";
cookBookTag[ 84 ] = "#84: 'with' statement is not supported";
cookBookTag[ 85 ] = "#85: Values computed at runtime are not supported in 'case' statements";
cookBookTag[ 86 ] = "#86: 'switch' statements cannot accept values of arbitrary types";
cookBookTag[ 87 ] = "#87: 'throw' statements cannot accept values of arbitrary types";
cookBookTag[ 88 ] = "#88: Each overloaded function should have its body";
cookBookTag[ 89 ] = "#89: Each overloaded function with optional parameters should have its body";
cookBookTag[ 90 ] = "#90: Function must have explicit return type";
cookBookTag[ 91 ] = "#91: Destructuring parameter declarations are not supported";
cookBookTag[ 92 ] = "#92: Nested functions are not supported";
cookBookTag[ 93 ] = "#93: Using 'this' inside stand-alone functions is not supported";
cookBookTag[ 94 ] = "#94: Generator functions are not supported";
cookBookTag[ 95 ] = "#95: Asynchronous functions are partially supported";
cookBookTag[ 96 ] = "#96: Type guarding is supported with 'instanceof' and 'as'";
cookBookTag[ 97 ] = "#97: `keyof` operator is not supported";
cookBookTag[ 98 ] = "#98: Spreading an array into function arguments is not supported";
cookBookTag[ 99 ] = "#99: Spread operator is not supported";
cookBookTag[ 100 ] = "#100: Spreading an object is not supported";
cookBookTag[ 101 ] = "";
cookBookTag[ 102 ] = "";
cookBookTag[ 103 ] = "#103: Declaration merging is not supported";
cookBookTag[ 104 ] = "#104: Interfaces cannot extend classes";
cookBookTag[ 105 ] = "#105: Property-based runtime type checks are not supported";
cookBookTag[ 106 ] = "#106: Constructor function type is not supported";
cookBookTag[ 107 ] = "#107: Constructor declarations";
cookBookTag[ 108 ] = "#108: Overloaded constructors with shared body are not supported";
cookBookTag[ 109 ] = "#109: Dynamic property declaration is not supported";
cookBookTag[ 110 ] = "";
cookBookTag[ 111 ] = "#111: Explicit values for enumeration constants are not supported";
cookBookTag[ 112 ] = "";
cookBookTag[ 113 ] = "#113: 'enum' declaration merging is not supported";
cookBookTag[ 114 ] = "#114: Namespaces cannot be used as objects";
cookBookTag[ 115 ] = "#115: Scripts and modules";
cookBookTag[ 116 ] = "#116: Non-declaration statements in namespaces are not supported";
cookBookTag[ 117 ] = "#117: Statement as top-level element";
cookBookTag[ 118 ] = "#118: Special import type declarations are not supported";
cookBookTag[ 119 ] = "#119: Importing a module for side-effects only is not supported";
cookBookTag[ 120 ] = "#120: 'import default as ...' is not supported";
cookBookTag[ 121 ] = "#121: 'require' is not supported";
cookBookTag[ 122 ] = "#122: 'export default' is not supported";
cookBookTag[ 123 ] = "#123: Renaming in export declarations is not supported";
cookBookTag[ 124 ] = "#124: Export list declaration is not supported";
cookBookTag[ 125 ] = "#125: Re-exporting is not supported";
cookBookTag[ 126 ] = "#126: 'export = ...' assignment is not supported";
cookBookTag[ 127 ] = "#127: Special export type declarations are not supported";
cookBookTag[ 128 ] = "#128: Shorthand ambient module declaraation is not supported";
cookBookTag[ 129 ] = "#129: Wildcards in module names are not supported";
cookBookTag[ 130 ] = "#130: UMD module definitions are not supported";
cookBookTag[ 131 ] = "#131: .js extension is not allowed in module identifiers";
cookBookTag[ 132 ] = "#132: 'new.target' is not supported";
cookBookTag[ 133 ] = "#133: Dynamic import expressions are not supported";
cookBookTag[ 134 ] = "#134: Definite assignment assertsions are not supported";
cookBookTag[ 135 ] = "#134: IIFEs as namespace declarations are not supported";
cookBookTag[ 137 ] = "#137: 'globalThis' is not supported";
cookBookTag[ 139 ] = "#139: Property declarations on functions are not supported";
cookBookTag[ 140 ] = "#140: Function.apply, Function.bind, Function.call are not supported";
cookBookTag[ 142 ] = "#142: 'as const' assertions are not supported";
cookBookTag[ 143 ] = "#143: Import assertions are not supported";
