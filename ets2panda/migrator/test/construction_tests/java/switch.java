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

import java.util.Random;

public class Switch {
    public static void main(String[] args) {
        int[] arr = {
                33, 11, 44, 63, 16, 55, 14, 31, 3, 4, 5, 18, 20, 47, 23, 6, 10, 22, 77, 24
        };
        Random rand = new Random();
        int i = rand.nextInt(arr.length);
        int num = arr[i];

        switch(num){
            case 44:
                System.out.println("Lewis Hamilton");
                break;
            case 5:
                System.out.println("Sebastian Vettel");
                break;
            case 14:
                System.out.println("Fernando Alonso");
                break;
            case 33:
                System.out.println("Max Verstappen");
                break;
            default:
                System.out.println("Not a World Champion ");
        }
    }
}
