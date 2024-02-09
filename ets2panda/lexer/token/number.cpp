/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "number.h"
#include "lexer/lexer.h"

#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <limits>

namespace ark::es2panda::lexer {
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init,bugprone-exception-escape)
Number::Number(util::StringView str, const std::string &utf8, NumberFlags flags) noexcept : str_(str), flags_(flags)
{
    Lexer::ConversionResult res;
    if ((flags & (NumberFlags::DECIMAL_POINT | NumberFlags::EXPONENT)) == 0) {
        const int64_t temp = Lexer::StrToNumeric(&std::strtoll, utf8.c_str(), res, 10);

        if (res == Lexer::ConversionResult::SUCCESS) {
            if (temp <= std::numeric_limits<int32_t>::max() && temp >= std::numeric_limits<int32_t>::min()) {
                num_ = static_cast<int32_t>(temp);
                return;
            }

            num_ = temp;
            return;
        }
        if (res == Lexer::ConversionResult::INVALID_ARGUMENT) {
            flags_ |= NumberFlags::ERROR;
        }
    }

    const double temp = Lexer::StrToNumeric(&std::strtod, utf8.c_str(), res);
    if (res == Lexer::ConversionResult::SUCCESS) {
        num_ = temp;
    } else if (res == Lexer::ConversionResult::INVALID_ARGUMENT) {
        flags_ |= NumberFlags::ERROR;
    } else if (res == Lexer::ConversionResult::OUT_OF_RANGE) {
        num_ = std::numeric_limits<double>::infinity();
    }
}
}  // namespace ark::es2panda::lexer
