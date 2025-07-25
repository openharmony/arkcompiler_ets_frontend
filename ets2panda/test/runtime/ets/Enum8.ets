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

enum StringEnum {
    A = "Apple",
    B = "Banana",
    C = "Cherry"
}

enum IntEnum {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4
}

enum ColorEnum {
    Red = 5,
    Green = 10,
    Blue = 15
}

enum StatusEnum {
    Active = 1,
    Inactive = 0
}

enum TemperatureEnum {
    Cold = 0,
    Warm = 20,
    Hot = 40
}

enum PermissionEnum {
    Read = 1,
    Write = 2,
    Execute = 4
}

enum NumberEnum {
    Ten = 10,
    Twenty = 20,
    Thirty = 30
}

enum VolumeEnum {
    Low = 1,
    Medium = 2,
    High = 3
}

function main() {
    assertEQ(StringEnum.A + StringEnum.B, "AppleBanana");
    assertTrue(StringEnum.A < StringEnum.B);
    assertTrue(StringEnum.A !== StringEnum.B);
    assertTrue(StringEnum.C > StringEnum.A);

    assertEQ(IntEnum.One + IntEnum.Two, 3);
    assertEQ(IntEnum.Three - IntEnum.One, 2);
    assertEQ(IntEnum.Four * IntEnum.Two, 8);
    assertEQ(IntEnum.Four / IntEnum.Two, 2);

    assertEQ(ColorEnum.Red + ColorEnum.Green, 15);
    assertEQ(ColorEnum.Blue - ColorEnum.Green > 0 ? "Greater" : "Smaller", "Greater");

    let status = StatusEnum.Active;
    assertTrue(status === StatusEnum.Active);
    assertTrue(status !== StatusEnum.Inactive);

    status = StatusEnum.Inactive;
    assertTrue(status === StatusEnum.Inactive);

    assertEQ(Number(TemperatureEnum.Cold) + 10, 10);
    assertEQ(Number(TemperatureEnum.Warm) * 2, 40);

    assertTrue((PermissionEnum.Read & PermissionEnum.Write) === 0);
    assertTrue((PermissionEnum.Read | PermissionEnum.Execute) === 5);
    assertTrue((PermissionEnum.Read ^ PermissionEnum.Write) === 3);

    assertEQ(NumberEnum.Ten + 10, 20);
    assertEQ(NumberEnum.Twenty - 10, 10);
    assertEQ(NumberEnum.Thirty * 2, 60);
    assertEQ(NumberEnum.Twenty / 2, 10);
    let volumeLevel = VolumeEnum.Medium;
    let message = volumeLevel === VolumeEnum.Low ? "Low Volume" : (volumeLevel === VolumeEnum.Medium ? "Medium Volume" : "High Volume");
    assertEQ(message, "Medium Volume");
}
