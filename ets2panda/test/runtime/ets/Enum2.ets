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

enum Color { Red, Green, Blue }

class ColorEnumDelegate {
  private static values_: Color[] = [Color.Red, Color.Green, Color.Blue];
  private static names_: String[] = ["Red", "Green", "Blue"];

  public static values(): Color[] { return ColorEnumDelegate.values_; }

  public static ordinal(x: Color): int { return x as int; }

  public static toString(x: Color): String { return ColorEnumDelegate.names_[x as int]; }

  public static valueOf(name: String): Color {
    for (let i = 0; i < ColorEnumDelegate.values_.length; i++) {
      if (ColorEnumDelegate.names_[i] == name) { return ColorEnumDelegate.values_[i]; }
    }

    assertTrue(false, "No enum constant Color")
    return Color.Red;
  }

  public static valueOf(ordinal: int): Color {
    if (0 <= ordinal && ordinal < ColorEnumDelegate.values_.length) {
      return ColorEnumDelegate.values_[ordinal];
    }

    assertTrue(false, "No enum constant Color")
    return Color.Red;
  }
}

function main(): void {
  let red: Color = Color.Red;
  assertEQ(ColorEnumDelegate.toString(red), "Red")

  assertEQ(ColorEnumDelegate.ordinal(red), 0)
  assertEQ(ColorEnumDelegate.ordinal(Color.Green), 1)

  assertEQ(ColorEnumDelegate.valueOf(2), Color.Blue)
  assertEQ(ColorEnumDelegate.valueOf(ColorEnumDelegate.ordinal(Color.Red)), red)

  assertEQ(ColorEnumDelegate.valueOf("Green"), Color.Green)
  assertEQ(ColorEnumDelegate.valueOf(ColorEnumDelegate.toString(Color.Blue)), Color.Blue)
}
