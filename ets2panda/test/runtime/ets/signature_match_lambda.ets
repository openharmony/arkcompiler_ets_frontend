/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

class A {
    catch<U = never>(onRejected: () => U | PromiseLike<U>): string {
        onRejected()
        return "first catch is matched"
    }
    catch<U = never>(onRejected: (error: Error) => U | PromiseLike<U>): string {
        onRejected(new Error())
        return "second catch is matched"
    }
    catch<U = never>(onRejected: (a: Error, b: Error) => U | PromiseLike<U>): string {
        onRejected(new Error(), new Error())
        return "third catch is matched"
    }
    catch<U = never>(onRejected: (a: Error, b: Error, c: Error) => U | PromiseLike<U>): string {
        onRejected(new Error(), new Error(), new Error())
        return "fourth catch is matched"
    }
}

function main(){
    let a = new A()
    assertEQ(a.catch(()=>{}),"first catch is matched")
    assertEQ(a.catch((e:Error|undefined|null)=>{}),"second catch is matched")
    assertEQ(a.catch((e:Error)=>{}),"second catch is matched")
    assertEQ(a.catch((e:Error,e2:Error)=>{}),"third catch is matched")
    assertEQ(a.catch((e:Error,e2:Error,e3:Error)=>{}),"fourth catch is matched")
}
