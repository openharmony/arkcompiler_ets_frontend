/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.test.java; 

// Java specification Example 8.1.2-2. Nested Generic Classes

class Seq<T> {
    T head;
    Seq<T> tail;
    Seq() { this(null, null); }
    Seq(T head, Seq<T> tail) {
        this.head = head;
        this.tail = tail;
    }

    boolean isEmpty() { return tail == null; }

    class Zipper<S> {
        Seq<Pair<T,S>> zip(Seq<S> that) {
            if (isEmpty() || that.isEmpty()) {
                return new Seq<Pair<T,S>>();
            } else {
                Seq<T>.Zipper<S> tailZipper = tail.new Zipper<S>();

                return new Seq<Pair<T,S>>(new Pair<T,S>(head, that.head), tailZipper.zip(that.tail));
            }
        }
    }
}

class Pair<T, S> {
    T fst;
    S snd;
    Pair(T f, S s) { fst = f; snd = s; }
}

class Test {
    public static void main(String[] args) {
        Seq<String> strs = new Seq<>("a", new Seq<String>("b", new Seq<String>()));
        Seq<Number> nums = new Seq<Number>(new Integer(1), new Seq<Number>(new Double(1.5), new Seq<Number>()));
        Seq<String>.Zipper<Number> zipper = strs.new Zipper<Number>();
        Seq<Pair<String,Number>> combined = zipper.zip(nums);
    }
}
