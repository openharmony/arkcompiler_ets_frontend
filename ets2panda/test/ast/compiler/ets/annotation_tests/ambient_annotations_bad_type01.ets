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

import * as Src from "./annotation_src"

@interface Src.ClassAuthor {
    /* @@ label */authorName: string = /* @@ label1 */"Jima"
    /* @@ label2 */authorAge: number = /* @@ label3 */-35.1
    /* @@ label4 */testBool: boolean = /* @@ label5 */true
    /* @@ label6 */favorColor: Src.Color = /* @@ label7 */Src.Color.RED
    /* @@ label8 */color: FixedArray<Src.Color> = /* @@ label9 */[/* @@ label10 */Src.Color.GREEN, Src.Color.BLUE]
    /* @@ label11 */reviewers: FixedArray<string> = /* @@ label12 */["Bob", "Jim", /* @@ label13 */"Tome"]
    /* @@ label14 */reviewersAge: FixedArray<double> = /* @@ label15 */[/* @@ label16 */11, 12, 32]
    /* @@ label17 */testBools: FixedArray<boolean> = /* @@ label18 */[/* @@ label19 */true, true, false]
    mutiArray: FixedArray<FixedArray<number>> = [
        [1, 2, 3],
        [4, +5, 6],
        [7, 8, -9]
    ]
}

/* @@@ label1 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label Error TypeError: Initializer for field 'authorName' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label3 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label2 Error TypeError: Initializer for field 'authorAge' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label5 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label4 Error TypeError: Initializer for field 'testBool' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label7 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label6 Error TypeError: Initializer for field 'favorColor' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label10 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label9 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label8 Error TypeError: Initializer for field 'color' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label13 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label12 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label11 Error TypeError: Initializer for field 'reviewers' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label16 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label15 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label14 Error TypeError: Initializer for field 'reviewersAge' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */
/* @@@ label19 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label18 Error TypeError: The initial value does not match the expected value.  */
/* @@@ label17 Error TypeError: Initializer for field 'testBools' does not match the expected definition in the ambient annotation 'ClassAuthor'.  */