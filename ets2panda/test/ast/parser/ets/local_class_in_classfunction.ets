/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
class A_class{
    localfield:string = "localstring";
    foo(){
        abstract class AbstractLocalClass{}
        class LocalClass extends AbstractLocalClass{
            method1():string{
                return localfield;
            }
        }
        final class FinalLocalClass{
            method1():string{
                return this.localfield;
            }
        }

        class ExtendsLocalClass extends FinalLocalClass{}
        abstract final class AbstractFinalLocalClass{}

        abstract class AbstractLocalClass2{
            method1(){}
        }
        let a:AbstractLocalClass2 = new AbstractLocalClass2();

        abstract class AbstractLocalClass3{
            abstract override method1()
            abstract method2(){}
        }
        
        final class FinalLocalClass2 extends AbstractLocalClass3{
            override method2(){}
            abstract method3()
        }

        
    }
}

/* @@? 21:24 Error TypeError: Property 'localfield' of enclosing class 'A_class' is not allowed to be captured from the local class 'LocalClass'  */
/* @@? 21:24 Error TypeError: Property 'localfield' must be accessed through 'this'  */
/* @@? 26:29 Error TypeError: Property 'localfield' does not exist on type 'FinalLocalClass'  */
/* @@? 30:41 Error TypeError: Cannot inherit with 'final' modifier.  */
/* @@? 31:53 Error TypeError: Cannot use both 'final' and 'abstract' modifiers.  */
/* @@? 36:37 Error TypeError: AbstractLocalClass2 is abstract therefore cannot be instantiated.  */
/* @@? 39:13 Error TypeError: Invalid method modifier(s): an abstract method can't have private, override, static, final or native modifier.  */
/* @@? 40:31 Error TypeError: Native, Abstract and Declare methods cannot have body.  */
/* @@? 43:65 Error TypeError: FinalLocalClass2 is not abstract and does not override abstract method method3(): void in FinalLocalClass2  */
/* @@? 45:13 Error TypeError: Non abstract class has abstract method.  */