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
function main():void
{
    let localint:int = 200;

    abstract class AbstractLocalClass{
        field1:int = 10;
    }

    class LocalClass extends AbstractLocalClass{
        field2:int = 20;
        static staticfield = 30;
        method1(){
            assertEQ(this.field1, 10)
            assertEQ(this.field2, 20)
            assertEQ(localint, 200)
        }
        static method2(){
            assertEQ(LocalClass.staticfield, 30)
        }
    }
    
    final class FinalLocalClass{
        field1:int = 10;
        static staticfield = 30;
        method1(){
            assertEQ(this.field1, 10)
            assertEQ(localint, 200)
        }
        static method2(){
            assertEQ(FinalLocalClass.staticfield, 30)
        }
    }

    let x:AbstractLocalClass = new LocalClass();
    assertEQ(x.field1, 10)
    assertEQ(x.field2, 20)
    assertEQ(LocalClass.staticfield, 30)
    x.method1();
    LocalClass.method2();

    let x2:FinalLocalClass = new FinalLocalClass();
    assertEQ(x2.field1, 10)
    assertEQ(FinalLocalClass.staticfield, 30)
    x2.method1()
    FinalLocalClass.method2();
}