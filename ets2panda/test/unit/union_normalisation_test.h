/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef PANDA_UNION_NORMALISATION_TEST_H
#define PANDA_UNION_NORMALISATION_TEST_H

#include "test/utils/checker_test.h"

namespace ark::es2panda::gtests {

class UnionNormalizationTest : public test::utils::CheckerTest {
public:
    UnionNormalizationTest() = default;
    ~UnionNormalizationTest() override = default;

    NO_COPY_SEMANTIC(UnionNormalizationTest);
    NO_MOVE_SEMANTIC(UnionNormalizationTest);

protected:
    static constexpr uint8_t SIZE2 = 2;
    static constexpr uint8_t SIZE3 = 3;
    static constexpr uint8_t IDX0 = 0;
    static constexpr uint8_t IDX1 = 1;
    static constexpr uint8_t IDX2 = 2;
};

}  // namespace ark::es2panda::gtests
#endif  // PANDA_UNION_NORMALISATION_TEST_H
