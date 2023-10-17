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

function main():void{
    assert foo1() == 10;
    assert foo2() == c'a';
    assert foo3() == true;

    assert foo4() == 30;
    assert foo4(5) == 25;

    assert foo5(5) == 55;
    assert foo5(5,10) == 45;


    assert foo6() == 0;
    assert foo7() == false;
    assert foo8() == c'\u0000';


    assert foo13(10) == 15;
    assert foo14(10) == 25;

    assert foo15(10,5) == 20;
    assert foo16(10,5) == 30;


    assert foo17(1,2) == 1;
    assert foo17(1,9999999999) == 2;

    assert foo18(1,2) == 1;
    assert foo18(1,false) == 2;

    assert foo19(1,2) == 1;
    assert foo19(1,c'a') == 2;
}

function foo1(a : int = 10) : int {
    return a;
}

function foo2(a : char = c'a') : char {
    return a;
}

function foo3(a : boolean = true) : boolean {
    return a;
}

function foo4(a : int = 10, b : int = 20) : int {
    return a + b;
}

function foo5(a : int = 10, b : int = 20, c : int = 30) : int {
    assert a == 5;

    return a + b + c;
}

function foo6(a? : int) : int {
    return a;
}

function foo7(a? : boolean) : boolean {
    return a;
}

function foo8(a? : char) : char {
    return a;
}

function foo13(a : int, b : int = 5) : int {
    return a + b;
}

function foo14(a : int, b : int = 5, c : int = 10) : int {
    return a + b + c;
}

function foo15(a : int, b : int, c : int = 5) : int {
    return a + b + c;
}

function foo16(a : int, b : int, c : int = 10, d : int = 5) : int {
    return a + b + c + d;
}

function foo17(a : int, b : int = 20, c : int = 30) : int {
    return 1;
}

function foo17(a : int, b : long = 20, c : int = 30) : int {
    return 2;
}

function foo18(a : int, b : int = 20, c : int = 30) : int {
    return 1;
}

function foo18(a : int, b : boolean = true, c : int = 30) : int {
    return 2;
}

function foo19(a : int, b : int = 20, c : int = 30) : int {
    return 1;
}

function foo19(a : int, b : char = c'a', c : int = 30) : int {
    return 2;
}
