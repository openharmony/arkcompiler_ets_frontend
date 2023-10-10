/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

class A_class {
    field: number = 1234 // Not visible for the local class
    method (parameter: number) {
        let local: string = "instance local"
        
        interface LocalInterface {
            method (): void
            field: string
        }
    
        class LocalClass implements LocalInterface {
            override method () { 
                console.log ("Instance field = " + this.field + " par = " + parameter + " loc = " +  local ) 
                assert(this.field == "`instance method instance field value`")
                assert(parameter == 42)
                assert(local == "instance local")

            }
            field: string = "`instance method instance field value`"
            static s_method () { 
                console.log ("Static field = " + LocalClass.s_field)
                assert(LocalClass.s_field == "`instance method class/static field value`")
            }
            static s_field: string = "`instance method class/static field value`"
        }
        
        let lc: LocalInterface = new LocalClass
        lc.method()
        LocalClass.s_method()
    }
    
    static s_method (parameter: number) {
        let local: string = "class/static local"
        interface LocalInterface {
            method (): void
            field: string
        }

        class LocalClass implements LocalInterface {
            override method () { 
                console.log ("Instance field = " + this.field + " par = " + parameter + " loc = " +  local) 
                assert(this.field == "`static method instance field value`")
                assert(parameter == 72)
                assert(local == "class/static local")
            }
            field: string = "`static method instance field value`"
            static s_method () { 
                console.log ("Static field = " + LocalClass.s_field) 
                assert(LocalClass.s_field == "`static method class/static field value`")
            }
            static s_field: string = "`static method class/static field value`"
        }
        let lc: LocalInterface = new LocalClass
        lc.method()
        LocalClass.s_method()
    }
}

function main() : int
{
    A_class.s_method(72);

    let a = new A_class();
    a.method(42)

    return 0;
}
