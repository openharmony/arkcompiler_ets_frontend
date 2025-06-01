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
    foo(){
        let localfield:string = "localstring";
        abstract class AbstractLocalClass{
            field1:int = 100;
        }
        class LocalClass extends AbstractLocalClass{
            field2:int = 200;
            static staticfield = 300;
            method1(){
                assertEQ(this.field1, 100)
                assertEQ(this.field2, 200)
                assertEQ(localfield, "localstring")
            }
            static method2(){
                assertEQ(LocalClass.staticfield, 300)
            }
        }
        final class FinalLocalClass{
            field1:int = 100;
            static staticfield = 300;
            method1(){
                assertEQ(this.field1, 100)
                assertEQ(localfield, "localstring")
            }
            static method2(){
                assertEQ(LocalClass.staticfield, 300)
            }
        }

        let x:AbstractLocalClass = new LocalClass();
        assertEQ(x.field1, 100)
        assertEQ(x.field2, 200)
        assertEQ(LocalClass.staticfield, 300)
        x.method1();
        LocalClass.method2();

        let x2:FinalLocalClass = new FinalLocalClass();
        assertEQ(x2.field1, 100)
        assertEQ(FinalLocalClass.staticfield, 300)
        x2.method1()
        FinalLocalClass.method2();
    }
}

function main():void
{
    let x3:A_class = new A_class;
    x3.foo();
}