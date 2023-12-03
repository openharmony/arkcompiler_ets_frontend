/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


class Foo {
    #field = 1;
    #method() { }
    static #staticField = 2;
    static #staticMethod() { }

    check(v: any) {
        print(#field in v);
        print(#method in v);
        print(#staticField in v);
        print(#staticMethod in v);
    }
    precedence(v: any) {
        print(v == #field in v || v);
        print(#field in v && #field in v);
    }
}

class Bar {
    #field = 1;
}

let f = new Foo();
let b = new Bar();

f.check(f);
f.check(b);

f.precedence(f);