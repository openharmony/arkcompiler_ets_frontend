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

public class binary_operations {
    private int sum1 = 3 + 2;
    private int sum2 = 3 + 2 - 4 + 1;
    private int sub1 = 8 - 3;
    private int sub2 = 8 - 3 + 8;
    private int rem1 = 5 % 3;
    private int rem2 = 5 % 3 - 2 * 8;
    private float mult1 = 6.2f * 3.14f;
    private double mult2 = 6.2 * (3.7 + 8.18) / 2.2;
    private float div1 = 4.2f / 2.3f;
    private double div2 = 4.2 / (2.2 - 0.1) + (3.3 / 6.1);
    private int lsh = 7 << 2;
    private int rsh1 = 7 >> 2;
    private int rsh2 = 7 >>> 2;
    private int bit1 = 7 & 3;
    private int bit2 = 7 | 3;
    private int bit3 = 7 ^ 3;
    private boolean b1 = 3 < 8;
    private boolean b2 = 3 <= 7;
    private boolean b3 = 3 >= 7;
    private boolean b4 = 3 > 8;
    private boolean b5 = 7 == 8;
    private boolean b6 = 7 != 4;
    private boolean b7 = (7 < 3) && (8 > 1);
    private boolean b8 = (7 < 3) || (8 > 1);
}
