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

#include "util/errorHandler.h"

namespace ark::es2panda::util {

void ErrorHandler::LogSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    errorLogger_->WriteLog(
        Error {ErrorType::SYNTAX, program_->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col});
}

void ErrorHandler::LogSyntaxError(util::ErrorLogger *errorLogger, const parser::Program *program,
                                  std::string_view errorMessage, const lexer::SourcePosition &pos)
{
    ErrorHandler(program, errorLogger).LogSyntaxError(errorMessage, pos);
}

}  // namespace ark::es2panda::util
