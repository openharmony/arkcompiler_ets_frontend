/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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


function main() : int
{
    let l_int = 0;

    class LocalClassLevel1
    {
        m_int1 = 11;

        method1()
        {
            let l_int2 = 12;
            assertEQ(this.m_int1, 11)
            assertEQ(l_int, 0)
            l_int = 1;

            class LocalClassLevel2
            {
                m_int2 : int = 22;

                method2() {
                    assertEQ(this.m_int2, 22)
                    assertEQ(l_int2, 12)
                    l_int2 = 13;
                }
            }

            let lcl2 = new LocalClassLevel2();
            lcl2.method2();
            assertEQ(l_int2, 13)
        }
    }

    let lcl1 = new LocalClassLevel1();
    lcl1.method1();
    assertEQ(l_int, 1)

    return 0;
}
