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

function caseClausesVariants(): void {
    let x = 0;

    // Empty switch
    switch (x) {}

    // No default clause    
    switch (x) {
        case 1:
            x = 10;
            break;
        case 2:
            x = 20;
            break;
    }

    // Only default case
    switch (x) {
        default:
            x = 31;
            break;
    }

    // Case clause followed by default
    switch (x) {
        case 1:
            x = 41;
            break;
        case 2:
            break;
        default:
            x = 43;
            break;
    }

    // Case clause following default clause
    switch (x) {
        default:
            x = 51;
            break;
        case 1:
            x = 52;
            break;
        case 2:
            x = 53;
            break;
    }

    // Case clauses before and after default clause
    switch (x) {
        case 1:
            x = 61;
            break;
        default:
            x = 62;
            break;
        case 2:
            x = 63;
            break;
    }

    // Fall-through 1
    switch (x) {
        case 1:
        case 2:
            console.log("Falling through case 1 and case 2");
            break;
        default:
            console.log("Default case");
            break;
    }

    // Fall-through 2
    switch (x) {
        case 1:
        default:
            console.log("Falling through both case and default clauses");
            break;
    }

    // Fall-through 3
    switch (x) {
        case 1:
            console.log("Case 1: Falling through to default case");
        default:
            console.log("Default case: falling through to case 2.");
        case 2:
            console.log("Case 2");
    }
}

function withReturns(x: number): string {
    // Return from switch
    switch (x) {
        case 1:
            return "One";
        case 2:
            return "Two";
        case 5:
            return "Five";
        default:
            return "NaN";
    }
}

enum Color {
    Red,
    Green,
    Blue
}

function withEnum(color: Color): void {
    switch (color) {
        case Color.Red:
            console.log("Color is red");
            break;
        case Color.Blue:
            console.log("Color is blue");
            break;
        default:
            console.log("Color is default");
            break;
    }
}

function withLocalDeclarations(): void {
    let i = 10;

    // Local variable is referenced across several case clauses.
    switch (i) {
        case 0:
            let q = 5;
            let w = q;      // This declaration is moved in front of switch. Initialization is turned into assignment.
            let e: number;  // This declaration is moved in front of switch. No initialization.
            break;
        default:
            w = 10;
            e = 20;
            console.log(w + e);
            break;
    }

    // Multiple variables in single variable declaration list.
    switch (i) {
        case 0:
            let q = 5, w, e = 10, r;    // 'q' and 'r' are moved in front of switch.
            let z = 20, x;              // Both 'z' and 'x' declarations are left in this block.
            console.log(q + e + z);
            break;
        default:
            q = 2;
            r = 4;
            console.log(q + r);
            break;
    }

    // Variable hiding.
    let localVar = "value";
    switch (i) {
        case 1:
            let localVar = 5; // Hides the outer string variable with the same name.
            break;
        case 2:
            {
                let localVar = true; // Hides both other 'localVar' variables in current block.
            }
            break;
        default:
            localVar = 10;
            break;
    }

    // Local variable is initialized with expression that can cause side-effects.
    // The order of evaluation of variable initializers must be preserved.
    switch (i) {
        case 0:
            let q = i++, w = i++, e = i++;
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
            let k = 10;

            switch (k) {
                case 3:
                    k = 20;
                    break;
                default:
                    console.log(k);
                    break;
            }

            break;
        default:
            break;
    }

    // Local variable is initialized with expression that can cause side-effects.
    // The order of evaluation of variable initializers must be preserved.
    switch (i) {
        case 0:
            function localF1() {
                console.log("Case clause");
            }
            localF2();
            break;
        default:
            function localF2() {
                console.log("Default clause");
            }
            localF1();
            break;
    }

    switch (i) {
        case 0:
            class C1 {}
            let c1 = new C1();
            break;
        default:
            class C2 {}
            let c2 = new C2();
            break;
    }
}

function withArbitraryExpressions(): void {
    switch (undefined) {
        case console.log(1):
        case console.log(2):
            void console.log(3);
    }

    let x = 10, y = 20, z = 30;
    let foo = (n: number) => n;
    switch (x) {
        case x + y:
            console.log("x + y = " + (x + y));
            break;
        case foo(z):
            console.log("foo(z) = " + foo(z));
            break;
        default:
            console.log("default case");
    }
}
