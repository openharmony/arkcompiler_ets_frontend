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
 
 public class CompoundAssignmentModulus {
    public static void main(String[] args) {
        //declaring variables
        int num1 = 5;
        int num2 = 3;

        //dividing two numbers, using compound modulus operator
        num1 %= num2;

        //printing new value of num1 variable
        System.out.println(num1);
}
}
