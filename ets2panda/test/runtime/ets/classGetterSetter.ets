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

interface inter {
    get my_field (): int;
    set my_field(param: int);
}

class A implements inter {
    my_field: int = 3;
}

function main() {
    let a0: A = new A();
    assert a0.my_field == 3;

    let a1: inter = new A();
    assert a1.my_field == 3;
    a1.my_field = 5;
    assert a1.my_field == 5;
}
