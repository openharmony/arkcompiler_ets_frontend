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

function f1() {
    var funProto = function(p) {
        this.p = p;
    };

    funProto.prototype = {
        m() {
            console.log(this.p);
        }
    };

    funProto.prototype.q = function(r) {
        return this.p === r;
    };
    
    function foo() {}
    foo.prototype = {};
    foo.prototype.prototype = {};
    let funProto2 = foo.prototype;
    funProto2.bar = 100;

    let ClassProto = class {
        p: number;
    }
    ClassProto.prototype = { p: 10 };
}

class X { }
class Y {
    prototype: number;
    xy: string;
}
function f2() {
    X.prototype = { };
    Y.prototype = { prototype: 20, xy: "" };
    let yProto = Y.prototype;
    new Y().prototype = 10; // Not a problem
}