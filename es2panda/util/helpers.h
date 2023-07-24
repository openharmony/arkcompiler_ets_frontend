/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_HELPERS_H
#define ES2PANDA_UTIL_HELPERS_H

#include <binder/variableFlags.h>
#include <mem/arena_allocator.h>
#include <os/file.h>
#include <util/ustring.h>

#include <cmath>

namespace panda::es2panda::ir {
class Expression;
class ScriptFunction;
class ClassDefinition;
class ClassProperty;
class Identifier;
class AstNode;
class ObjectExpression;
class StringLiteral;
}  // namespace panda::es2panda::ir

namespace panda::es2panda {
struct CompilerOptions;
}  // namespace panda::es2panda

namespace panda::pandasm {
struct Program;
}  // namespace panda::pandasm

namespace panda::es2panda::lexer {
class LineIndex;
}

namespace panda::es2panda::util {

enum class SignedNumberLiteral {
    UNRECOGNIZED = 0,
    POSITIVE = 1,
    NEGATIVE = 2
};

class Helpers {
public:
    Helpers() = delete;

    static bool IsGlobalIdentifier(const util::StringView &str);
    static bool ContainSpreadElement(const ArenaVector<ir::Expression *> &args);
    static util::StringView LiteralToPropName(ArenaAllocator *allocator, const ir::Expression *lit);

    template <typename T>
    static bool IsInteger(double number);
    static bool IsIndex(double number);
    static int64_t GetIndex(const util::StringView &str);

    static bool FileExtensionIs(std::string_view filePath, std::string_view extension);
    static bool EndsWith(std::string_view str, std::string_view suffix);
    static std::string DoubleToString(double number);
    static int32_t GetIntegerSignificandBitCount(double number, int32_t &numberBitCount, char *significandArray);
    static void GetScientificNotationForDouble(double number, uint32_t significandBitCount, int32_t &numberBitCount,
                                               char *significandArray, char *sciNotationArray, uint32_t size);
    static std::string ToString(double number);
    static util::StringView ToStringView(ArenaAllocator *allocator, double number);
    static util::StringView ToStringView(ArenaAllocator *allocator, int32_t number);
    static util::StringView ToStringView(ArenaAllocator *allocator, uint32_t number);

    static const ir::ScriptFunction *GetContainingConstructor(const ir::AstNode *node);
    static const ir::ScriptFunction *GetContainingConstructor(const ir::ClassProperty *node);
    static const ir::ScriptFunction *GetContainingFunction(const ir::AstNode *node);
    static const ir::ClassDefinition *GetClassDefiniton(const ir::ScriptFunction *node);
    static bool IsSpecialPropertyKey(const ir::Expression *expr);
    static bool IsConstantPropertyKey(const ir::Expression *expr, bool isComputed);
    static bool IsConstantExpr(const ir::Expression *expr);
    static bool IsBindingPattern(const ir::AstNode *node);
    static bool IsPattern(const ir::AstNode *node);
    static std::vector<const ir::Identifier *> CollectBindingNames(const ir::AstNode *node);
    static util::StringView FunctionName(ArenaAllocator *allocator, const ir::ScriptFunction *func);
    static std::tuple<util::StringView, bool> ParamName(ArenaAllocator *allocator, const ir::AstNode *param,
                                                        uint32_t index);
    static bool IsChild(const ir::AstNode *parent, const ir::AstNode *child);
    static bool IsObjectPropertyValue(const ArenaVector<ir::Expression *> &properties, const ir::AstNode *ident);
    static SignedNumberLiteral GetSignedNumberLiteral(const ir::Expression *expr);

    static void OptimizeProgram(panda::pandasm::Program *prog, const std::string &inputFile);
    template <typename T>
    static T BaseName(T const &path, T const &delims = std::string(panda::os::file::File::GetPathDelim()));
    static bool ReadFileToBuffer(const std::string &file, std::stringstream &ss);
    static void ScanDirectives(ir::ScriptFunction *func, const lexer::LineIndex &lineIndex);
    static std::string GetHashString(std::string str);
    static std::wstring Utf8ToUtf16(const std::string &utf8);
    template <typename T, typename... Args>
    static T FileStream(const std::string &str, Args &&...args);

    static const uint32_t MAX_DOUBLE_DIGIT = 310;
    static const uint32_t MAX_DOUBLE_PRECISION_DIGIT = 17;
    static const int32_t MAX_DECIMAL_EXPONENT = 21;
    static const int32_t MIN_DECIMAL_EXPONENT = -6;
    static const int32_t FAIL_SNPRINTF_S  = -1;
    static const uint32_t INVALID_INDEX = 4294967295L;
    static const uint32_t MAX_INT32 = 2147483647;
    static const uint32_t MAX_INT16 = std::numeric_limits<int16_t>::max();
    static const uint32_t MAX_INT8 = std::numeric_limits<int8_t>::max();
    static constexpr std::string_view SHOW_SOURCE = "show source";
    static constexpr std::string_view USE_CONCURRENT = "use concurrent";
    static const uint64_t FNV_PRIME = 1099511628211U;
    static const uint64_t FNV_OFFSET = 14695981039346656037U;
private:
    static bool SetFuncFlagsForDirectives(const ir::StringLiteral *strLit, ir::ScriptFunction *func,
                                          const lexer::LineIndex &lineIndex);
};

template <typename T>
bool Helpers::IsInteger(double number)
{
    if (std::fabs(number) <= static_cast<double>(std::numeric_limits<T>::max())) {
        T intNum = static_cast<T>(number);

        if (static_cast<double>(intNum) == number) {
            return true;
        }
    }

    return false;
}

template <class T>
T Helpers::BaseName(T const &path, T const &delims)
{
    return path.substr(path.find_last_of(delims) + 1);
}

template <typename T, typename... Args>
T Helpers::FileStream(const std::string &str, Args &&...args)
{
    T fileStream;
#ifdef PANDA_TARGET_WINDOWS
    std::wstring filename = Helpers::Utf8ToUtf16(str);
#else  //for linux and mac
    std::string filename = str;
#endif
    fileStream.open(filename.c_str(), args...);
    return fileStream;
}

}  // namespace panda::es2panda::util

#endif
