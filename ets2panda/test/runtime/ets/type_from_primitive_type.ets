 /*
  * Copyright (c) 2025 Huawei Device Co., Ltd.
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License from the specific language governing permissions and
  * limitations under the License.
  */

function main(){
   let byte1  = Type.from<byte>();
   let byte2  = Type.from<byte>();
   let byte3  = Type.from<Byte>();
   assertTrue(byte1 == byte2)
   assertTrue(byte1 != byte3)

   let char1  = Type.from<char>();
   let char2  = Type.from<char>();
   let char3  = Type.from<Char>();
   assertTrue(char1 == char2)
   assertTrue(char1 != char3)

   let short1  = Type.from<short>();
   let short2 = Type.from<short>();
   let short3  = Type.from<Short>();
   assertTrue(short1 == short2)
   assertTrue(short1 != short3)

   let int1  = Type.from<int>();
   let int2  = Type.from<int>();
   let int3  = Type.from<Int>();
   assertTrue(int1 == int2)
   assertTrue(int1 != int3)

   let long1  = Type.from<long>();
   let long2  = Type.from<long>();
   let long3  = Type.from<Long>();
   assertTrue(long1 == long2)
   assertTrue(long1 != long3)

   let float1  = Type.from<float>();
   let float2  = Type.from<float>();
   let float3  = Type.from<Float>();
   assertTrue(float1 == float2)
   assertTrue(float1 != float3)

   let double1  = Type.from<double>();
   let double2  = Type.from<double>();
   let double3  = Type.from<Double>();
   assertTrue(double1 == double2)
   assertTrue(double1 != double3)


   let number1  = Type.from<number>();
   let number2  = Type.from<number>();
   let number3  = Type.from<Number>();
   assertTrue(number1 == number2)
   assertTrue(number1 != number3)


   let boolean1  = Type.from<boolean>();
   let boolean2 = Type.from<boolean>();
   let boolean3  = Type.from<Boolean>();
   assertTrue(boolean1 == boolean2)
   assertTrue(boolean1 != boolean3)

  let void1  = Type.from<void>();
  let void2 = Type.from<void>();
  let void3  = Type.from<Void>();
  assertTrue(void1 == void2)
  assertTrue(void1 != void3)



   }
