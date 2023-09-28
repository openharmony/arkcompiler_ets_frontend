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
 
 public class LabelledBreak {
    public static void main(String[] args) {
        int[] []arr = {
                {33, 11}, {44, 63}, {16, 55}, {14, 31}, {3, 4}, {5, 18}, {20, 47}, {23, 6}, {10, 22}, {77, 24}
        };
        int search = 5;

        SomeLabel:
        for (int i = 0; i < arr.length; i++){
            for (int j = 0; j < arr[i].length; j++) {
                if (arr[i][j] == search) {
                    break SomeLabel;
                }
            }
        }
        System.out.println("Found");
    }
}