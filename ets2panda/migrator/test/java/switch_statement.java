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

public class switch_statement {

    public static String ReturnFromSwitch(int id) {
        switch (id) {
            case 1:
                return "First";
            case 2:
                return "Second";
            default:
                return "Unknown";
        }
    }

    public static void CaseClausesVariations() {
        int a = 0;

        // empty switch
        switch (1) {
        }

        // no default clause
        switch (2) {
            case 1:
                a = 21;
                break;
            case 2:
                a = 22;
                break;
        }

        // only default case
        switch (3) {
            default:
                a = 31;
                break;
        }

        // case clause followed by default
        switch (4) {
            case 1:
                a = 41;
                break;
            case 2:
                break;
            default:
                a = 43;
                break;
        }

        // case clause following default clause
        switch (5) {
            default:
                a = 51;
                break;
            case 1:
                a = 52;
                break;
            case 2:
                a = 53;
                break;
        }

        // case clauses before and after default clause
        switch (6) {
            case 1:
                a = 61;
                break;
            default:
                a = 62;
                break;
            case 2:
                a = 63;
                break;
        }

        // Fall-through
        switch (7) {
            case 1:
            case 2:
                System.out.println("Falling through case 1 and case 2");
                break;
            default:
                System.out.println("Default case");
                break;
        }

        // Fall-through
        switch (8) {
            case 1:
            default:
                System.out.println("Falling through both case and default clauses");
                break;
        }

        // Fall-through
        switch (9) {
            case 1:
                System.out.println("In case 1: Falling through to default case");
            default:
                System.out.println("In default case");
                break;
            case 2:
                System.out.println("In case 2");
                break;
        }
    }

    public static void SwitchWithLocalDeclarations() {
        int i = 10;

        // Local variable is referenced across several case clauses.
        switch (i) {
            case 0:
                int q = 5;
                int w = q; // This declaration is moved in front of switch. Initialization is turned into assignment.
                int e; // This declaration is moved in front of switch. No initialization.
                break;
            default:
                w = 10;
                e = 20;
                System.out.println(w + e);
                break;
        }

        // Multiple variables in single variable declaration list.
        switch (i) {
            case 0:
                int q = 5, w, e = 10, r; // 'q' and 'r' are moved in front of switch.
                int z = 20, x; // Both 'z' and 'x' declarations are left in this block.
                System.out.println(q + e + z);
                break;
            default:
                q = 2;
                r = 4;
                System.out.println(q + r);
                break;
        }

        // Block variable and hiding.
        switch (i) {
            case 1:
                {
                    String localVar = "some value"; // 'String localVar' will hide the 'int localVar' in current block scope.
                }
                break;
            case 2:
                int localVar = 5;
                break;
            default:
                localVar = 6;
                break;
        }

        // Local variable is initialized with expression that can cause side-effects.
        // The order of evaluation of variable initializers must be preserved.
        switch (i) {
            case 0:
                int q = i++, w = i++, e = i++;
                break;
            default:
                q = 1;
                e = 2;
                break;
        }

        // Variable 'k' is referenced from nested switch, though, it's still being used
        // only within the case clause it was declared in.
        switch (i) {
            case 1:
                int k = 10;

                switch (i) {
                    case 3:
                        k = 20;
                        break;
                    default:
                        break;
                }

                break;
            default:
                break;
        }

        // Switch with local class declaration
        switch (i) {
            case 1:
                class LocalClass {
                    void M() {
                        System.out.println("LocalClass.M()");
                    }
                }
                new LocalClass().M();
                break;
            default:
                break;
        }
    }

    enum Color {
        Red,
        Green,
        Blue
    }

    private static void SwitchWithEnumValues() {
        Color color = Color.Green;

        switch (color) {
            case Red:
                System.out.println("Color is red");
                break;
            case Blue:
                System.out.println("Color is blue");
                break;
            default:
                System.out.println("Color is default");
                break;
        }
    }
}
