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

interface I {
    private xyz(): int {
        return 5;
    }

    xyz2(): int {
        return 5;
    }
}

class C implements I {
    override xyz2(): int {
        return 10;
    }
}

function main(): void {
    let i: I = new C();
    i.xyz();
}

/* @@? 34:5 Error TypeError: Signature xyz(): int is not visible here.  */
/* @@? 34:5 Error TypeError: No matching call signature  */
