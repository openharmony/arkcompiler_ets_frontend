/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

function foo (parameter: number) {
    let local: string = "function local";
    interface LocalInterface { // Local interface in a top-level function
        method (): void;   // It has a method
        field: string;     // and a property
    }
    class LocalClass implements LocalInterface { // Class implements interface
        // Local class in a top-level function
        override method () { 
            console.log ("Instance field = " + this.field + " par = " + parameter  + " loc = " +  local )
            assertEQ(this.field, "`instance field value`")
            assertEQ(parameter, 42)
            assertEQ(local, "function local")
        }
        field: string = "`instance field value`"
        static s_method () { 
            console.log ("Static field = " + LocalClass.s_field) 
            assertEQ(LocalClass.s_field, "`class/static field value`")

        }
        static s_field: string = "`class/static field value`"
    }

    let lc: LocalInterface = new LocalClass();
    // Both local types can be freely used in the top-level function scope
    lc.method()
    LocalClass.s_method()
}

function main() : int
{
    foo(42);
    return 0;
}
