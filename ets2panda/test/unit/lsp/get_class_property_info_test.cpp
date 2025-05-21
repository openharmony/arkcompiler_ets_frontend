/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "es2panda.h"
#include "lsp/include/api.h"
#include "lsp/include/get_class_property_info.h"
#include "lsp/include/cancellation_token.h"
#include "lsp_api_test.h"
#include <iostream>

namespace {
// NOLINTBEGIN
using ark::es2panda::lsp::Initializer;

class LspGetClassPropertyInfoTests : public LSPAPITests {};
std::vector<std::string> fileNames = {"GetClassPropertyInfoFile.ets"};
std::vector<std::string> fileContents = {
    R"(
enum BloodType {
  A = 'A',
  AB = 'AB'
}

class Address {
  province: string = '';
  city: string = '';
}

interface Control {
  state: number
}

interface SelectableControl extends Control {
  select(): void
}

class SelectableControlClass extends Address implements SelectableControl {
  select(): void {
    throw new Error("Method not implemented.");
  }

  private state1: number = 0;
  protected readonly hobbies: string[] = [];
}

enum Sex {
  Male = 'Male'
}

export class Person extends SelectableControlClass implements SelectableControl {
  static MAX_HEIGHT: number = 250;
  static BLOOD_TYPES: BloodType = BloodType.AB;
  static defaultAddress: Address = {
    province: '北京',
    city: '北京市',
  };
  name: string = '';
  age: number = Person.MAX_HEIGHT;
  weight: number = 0;
  sex: Sex = Sex.Male;
  bloodType: BloodType = BloodType.A;
  address: Address = new Address();
  hobbies: string[] = [];
  maritalStatus: 'single' | 'married' | 'divorced' = 'single';
  birthday: Date = new Date();
  location: [number, number] = [0, 0];
  avatar: Resource = $r('app.media.startIcon');
  attributes: Map<string, object> = new Map();
  isEmployed: boolean = false;
  private privateIsEmployed: boolean = false;
  protected protectedIsEmployed: boolean = false;
  protected readonly readonlyIsEmployed: boolean = false;
  onUpdate: (() => void) | null = null;
}
)"};
std::vector<std::tuple<std::string, size_t, size_t, std::string, std::vector<std::string>>> expectedResult = {
    {"MAX_HEIGHT", 561, 585, "classField", {"public", "static"}},
    {"BLOOD_TYPES", 596, 633, "classField", {"public", "static"}},
    {"defaultAddress", 644, 722, "classField", {"public", "static"}},
    {"name", 726, 743, "classField", {"public"}},
    {"age", 747, 778, "classField", {"public"}},
    {"weight", 782, 800, "classField", {"public"}},
    {"sex", 804, 823, "classField", {"public"}},
    {"bloodType", 827, 861, "classField", {"public"}},
    {"address", 865, 898, "classField", {"public"}},
    {"hobbies", 901, 923, "classField", {"public"}},
    {"maritalStatus", 927, 986, "classField", {"public"}},
    {"birthday", 990, 1018, "classField", {"public"}},
    {"location", 1021, 1056, "classField", {"public"}},
    {"avatar", 1060, 1104, "classField", {"public"}},
    {"attributes", 1108, 1152, "classField", {"public"}},
    {"isEmployed", 1155, 1182, "classField", {"public"}},
    {"privateIsEmployed", 1194, 1228, "classField", {"private"}},
    {"protectedIsEmployed", 1242, 1278, "classField", {"protected"}},
    {"readonlyIsEmployed", 1301, 1336, "classField", {"protected", "readonly"}},
    {"onUpdate", 1340, 1376, "classField", {"public"}}};

void CheckClassPropertiesMatch(const std::vector<FieldListProperty> &actualProperties)
{
    for (size_t i = 0; i < actualProperties.size(); ++i) {
        const auto &perp = actualProperties[i];
        const auto &expected = expectedResult[i];

        const auto &expectedName = std::get<0>(expected);
        const auto expectedStart = std::get<1>(expected);
        const auto expectedEnd = std::get<2>(expected);
        const auto &expectedKind = std::get<3>(expected);
        const auto &expectedModifiers = std::get<4>(expected);

        bool nameMatch = (perp.displayName == expectedName);
        bool startMatch = (perp.start == expectedStart);
        bool endMatch = (perp.end == expectedEnd);
        bool kindMatch = (perp.kind == expectedKind);

        bool modifiersMatch = true;
        if (perp.modifierKinds.has_value()) {
            const auto &actualModifiers = perp.modifierKinds.value();
            modifiersMatch = (actualModifiers == expectedModifiers);  // 严格比较顺序
        } else {
            modifiersMatch = expectedModifiers.empty();
        }

        bool currentMatch = nameMatch && startMatch && endMatch && kindMatch && modifiersMatch;
        ASSERT_EQ(true, currentMatch);
    }
}

TEST_F(LspGetClassPropertyInfoTests, GetClassPropertyInfoMethod1)
{
    constexpr size_t EXPECTED_CLASS_COUNT = 3;
    constexpr size_t EXPECTED_CLASS_COUNT_ONE = 1;
    constexpr size_t EXPECTED_PROP_COUNT = 20;

    auto filePaths = CreateTempFile(fileNames, fileContents);
    std::vector<ark::es2panda::SourceFile> sourceFiles;

    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(filePaths[i], fileContents[i]);
    }
    ASSERT_EQ(fileNames.size(), sourceFiles.size());

    Initializer initializer;
    size_t sourceIndex = 0;
    size_t tokenOffset = 800;
    auto filePath = std::string {sourceFiles[sourceIndex].filePath};
    auto fileContent = std::string {sourceFiles[sourceIndex].source};
    auto context = initializer.CreateContext(filePath.c_str(), ES2PANDA_STATE_CHECKED, fileContent.c_str());

    auto infos = ark::es2panda::lsp::GetClassPropertyInfo(context, tokenOffset, true);
    ASSERT_EQ(EXPECTED_CLASS_COUNT, infos.size());

    auto infos2 = ark::es2panda::lsp::GetClassPropertyInfo(context, tokenOffset);
    initializer.DestroyContext(context);
    ASSERT_EQ(EXPECTED_CLASS_COUNT_ONE, infos2.size());

    FieldsInfo info = infos2[0];
    ASSERT_EQ(EXPECTED_PROP_COUNT, info.properties.size());
    ASSERT_EQ("Person", info.name);
    CheckClassPropertiesMatch(info.properties);
}
// NOLINTEND
}  // namespace