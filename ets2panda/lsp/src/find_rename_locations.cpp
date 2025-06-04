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
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <ctime>
#include <string>

#include "find_rename_locations.h"
#include "find_references.h"

namespace ark::es2panda::lsp {

std::set<RenameLocation> FindRenameLocations(CancellationToken *tkn,
                                             const std::vector<ark::es2panda::SourceFile> &files,
                                             const ark::es2panda::SourceFile &file, size_t position)
{
    auto references = FindReferences(tkn, files, file, position);
    std::set<RenameLocation> res;

    for (auto ref : references) {
        auto srcIt = std::find_if(files.begin(), files.end(), [&ref](const SourceFile &currentFile) {
            return currentFile.filePath == ref.filePath;
        });
        if (srcIt == files.end()) {
            std::cout << "Error: Could not find " << ref.filePath << " in list!\n";
            continue;
        }
        std::string source = std::string {srcIt->source};
        // Get prefix and suffix texts
        std::string prefix;
        {
            auto end = source.begin() + ref.start;
            auto beg = end;
            while (beg > source.begin() && *(beg - 1) != '\n') {
                --beg;
            }
            prefix = std::string {beg, end};
        }
        // Suffix
        std::string suffix;
        {
            auto beg = source.begin() + ref.end;
            auto end = beg;
            while (end < source.end() && *end != '\n') {
                ++end;
            }
            suffix = std::string {beg, end};
        }
        res.insert(RenameLocation {ref.filePath, ref.start, ref.end, ref.line, prefix, suffix});
    }

    return res;
}

std::set<RenameLocation> FindRenameLocations(const std::vector<ark::es2panda::SourceFile> &files,
                                             const ark::es2panda::SourceFile &file, size_t position)
{
    time_t tmp = 0;
    CancellationToken cancellationToken {tmp, nullptr};
    return FindRenameLocations(&cancellationToken, files, file, position);
}
}  // namespace ark::es2panda::lsp