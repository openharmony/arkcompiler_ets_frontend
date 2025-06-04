/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

enum Color { Green , Red = 2, Blue }
//let cons = new Console; 

function main(): void {

  try {
    let name = Color.Blue.getName();
    let value:string = Color.getValueOf("Blue").toString();
    assertEQ(name, "Blue")
    assertEQ(value, "3")
    //cons.print(name + " = " + value + c'\n');
  } catch (e) {
    assertTrue((e as Object).toString().startsWith("No enum constant Color.Blue"))
  }

  let x: int = Color.Red.valueOf();
  assertEQ(x, 2)

  let blue = Color.Blue;
  let str = blue.getName();
  //cons.print("Color.Blue = '" + str + "'\n");
  assertEQ("Blue", str)

  let values = Color.values();
  assertEQ(values.length, 3)
  assertEQ(values[1], Color.Red)
  assertEQ(values[0], Color.Green)
  assertEQ(values[2], Color.Blue)

  let red1: Color = Color.Red;
  let red2: Color = Color.Green;
  assertEQ(red2 as int, 0)
  assertEQ(red2.valueOf(), 0)
  assertEQ(red2.getName(), "Green")
  assertEQ(red2.toString(), "0")
  //cons.print("\nDefault ordinal = " + red2 as int + ", value = " + red2.valueOf() + ", name: '" + red2.getName() + "', ToString: '" + red2.toString() + "'\n\n")
  
  try {
    red2 = Color.getValueOf("Red");
  } catch (e) {
    assertTrue((e as Object).toString().startsWith("No enum constant Color.Red"))
    //cons.print(e.toString() + "\n");
  }

  //cons.print( "GetName: Color.Red: '" + Color.Red.getName() + "', = Red: '" + red1.getName() + "', ValueOf(Red): '" + red2.getName() + "'\n")
  //cons.print( "GetValue: Color.Red = " + Color.Red.valueOf() + ", = Red = " + red1.valueOf() + ", ValueOf(Red) = " + red2.valueOf() + "\n")
  //cons.print( "Ordinal (as int): Color.Red = " + Color.Red as int + ", = Red = " + red1 as int + ", ValueOf(Red) = " + red2 as int + "\n")
  //cons.print( "ToString: Color.Red = '" + Color.Red.toString() + "', = Red = '" + red1.toString() + "', ValueOf(Red) = '" + red2.toString() + "'\n")

  assertEQ(red1 as int, 2)
  assertEQ(red1.valueOf(), 2)
  assertEQ(red1.getName(), "Red")
  assertEQ(red1.toString(), "2")

  assertEQ(red2 as int, 2)
  assertEQ(red2.valueOf(), 2)
  assertEQ(red2.getName(), "Red")
  assertEQ(red2.toString(), "2")

  assertEQ(red1, Color.Red)
  assertEQ(red2, Color.Red)
  assertEQ(red2, red1)

  let ord: int = 3;
  blue = ord as Color;
  assertEQ(blue as int, 3)
  assertEQ(blue.valueOf(), 3)
  assertEQ(blue.getName(), "Blue")
  assertEQ(blue.toString(), "3")

  try {
    let yellow: Color = Color.getValueOf("Yellow");
    assertTrue( false)
  } catch (e: Error) {
    assertTrue( (e as Object).toString().startsWith("Error: No enum constant Color.Yellow"))
  } catch (e) {}

  ord = 0;
  let green: Color = ord as Color;
  //cons.print("Green = " + green as int + ", Color.Green = " + Color.Green as int + "\n")
  assertEQ(green, Color.Green)

  try {
    let x = 5 as Color;
    assertTrue( false)
  } catch (e: Error) {
    assertTrue( (e as Object).toString().startsWith("Error: No enum Color with value 5"))
  }

  assertEQ( 2 as Color as int, 2)
  assertEQ( Color.Blue as int as Color, Color.Blue)
  assertEQ( (Color.Green as int + 2) as Color, (Color.Blue as int - 1) as Color)
  try {
    assertEQ((Color.Green as int + 1) as Color, Color.getValueOf("Red"))
  } catch (e) {
  }
}
