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

enum Color { Green = "red" , Red = "blue", Blue = "green" }

function main(): void {

  try {
    let name = Color.Blue.getName();
    let value:string = Color.getValueOf("Blue").toString();
    assertEQ(name, "Blue")
    assertEQ(value, "green")
  } catch (e) {
    assertTrue((e as Object).toString().startsWith("No enum constant Color.Blue"))
  }

  let x = Color.Red.valueOf();
  assertEQ(x, "blue")

  let blue = Color.Blue;
  let str = blue.getName();
  assertEQ( "Blue", str)
  assertEQ( blue.valueOf(), blue.toString())

  let values = Color.values();
  assertEQ(values.length, 3)
  assertEQ(values[1], Color.Red)
  assertEQ(values[0], Color.Green)
  assertEQ(values[2], Color.Blue)

  let red1: Color = Color.Red;
  let red2: Color = Color.Green;
  assertEQ(red2 as string, "red")
  assertEQ(red2.valueOf(), "red")
  assertEQ(red2.getName(), "Green")
  assertEQ(red2.toString(), "red")

  try {
    red2 = Color.getValueOf("Red");
  } catch (e) {
    assertTrue( (e as Object).toString().startsWith("No enum constant Color.Red"))
  }

  assertEQ(red1 as string, "blue")
  assertEQ(red1.valueOf(), "blue")
  assertEQ(red1.getName(), "Red")
  assertEQ(red1.toString(), "blue")

  assertEQ(red2 as string, "blue")
  assertEQ(red2.valueOf(), "blue")
  assertEQ(red2.getName(), "Red")
  assertEQ(red2.toString(), "blue")

  assertEQ(red1, Color.Red)
  assertEQ(red2, Color.Red)
  assertEQ(red2, red1)

  let ord: string = "green";
  blue = ord as Color;
  assertEQ(blue as string, "green")
  assertEQ(blue.valueOf(), "green")
  assertEQ(blue.getName(), "Blue")
  assertEQ(blue.toString(), "green")

  try {
    let yellow: Color = Color.getValueOf("Yellow");
    assertTrue(false)
  } catch (e: Exception) {
    assertTrue((e as Object).toString().startsWith("No enum constant Color.Yellow"))
  } catch (e) {}

  ord = "red";
  let green: Color = ord as Color;
  assertEQ( green, Color.Green)

  try {
    let x = "a" as Color;
    assertTrue( false)
  } catch (e: Error) {
    assertTrue( (e as Object).toString().startsWith("Error: No enum Color with value a"))
  }

  assertEQ( "red" as Color as string, "red")
  assertEQ( Color.Blue as string as Color, Color.Blue)
  try {
    assertEQ( (Color.Green as string) as Color, Color.getValueOf("red"))
  } catch (e) {
  }
}
