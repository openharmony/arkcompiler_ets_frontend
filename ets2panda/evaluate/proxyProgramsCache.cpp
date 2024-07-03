/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "evaluate/proxyProgramsCache.h"
#include "parser/program/program.h"

namespace ark::es2panda::evaluate {

ProxyProgramsCache::ProxyProgramsCache(ArenaAllocator *allocator) : cache_(allocator->Adapter()) {}

parser::Program *ProxyProgramsCache::GetProgram(util::StringView fileName)
{
    auto iter = cache_.find(fileName);
    return (iter == cache_.end()) ? nullptr : iter->second;
}

void ProxyProgramsCache::AddProgram(parser::Program *program)
{
    ASSERT(program);

    auto filePath = program->SourceFilePath();
    ASSERT(cache_.find(filePath) == cache_.end());

    cache_.emplace(filePath, program);
}

}  // namespace ark::es2panda::evaluate
