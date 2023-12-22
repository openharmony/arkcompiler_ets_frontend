/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <string>
#include "os/filesystem.h"
#include "path.h"

namespace panda::es2panda::util {

Path::Path() = default;

Path::Path(const util::StringView &absolute_path, ArenaAllocator *allocator)
{
    Initializer(absolute_path.Mutf8(), allocator);
}

void Path::Initializer(const std::string &path, ArenaAllocator *allocator)
{
    is_relative_ = false;
    allocator_ = allocator;
    path_ = util::UString(path, allocator).View();

    if (*(path_.Bytes()) == '.') {
        is_relative_ = true;
    }

    if (is_relative_) {
        absolute_path_ = util::UString(os::GetAbsolutePath(path_.Utf8()), allocator_).View();
    } else {
        absolute_path_ = path_;
    }

    InitializeFileExtension();
    InitializeFileName();
    InitializeParentFolder();
    InitializeAbsoluteParentFolder();
}

void Path::InitializeFileName()
{
    if (path_.Empty()) {
        return;
    }

    int position = path_.Mutf8().find_last_of(PATH_DELIMITER);

    util::StringView file_name = path_.Substr(position + 1, path_.Length());
    if (GetExtension().Empty()) {
        file_name_ = file_name;
    } else {
        int extension_position = file_name.Mutf8().find_last_of('.');
        file_name_ = file_name.Substr(0, extension_position);
    }
}

void Path::InitializeFileExtension()
{
    if (path_.Empty()) {
        return;
    }

    size_t position = path_.Mutf8().find_last_of('.');
    if (position != std::string::npos && position + 1 <= path_.Length()) {
        file_extension_ = path_.Substr(position + 1, path_.Length());
    }
}

void Path::InitializeAbsoluteParentFolder()
{
    if (path_.Empty()) {
        return;
    }

    int position = absolute_path_.Mutf8().find_last_of(PATH_DELIMITER);

    if (!absolute_path_.Empty() && is_relative_) {
        absolute_parent_folder_ = absolute_path_.Substr(0, position);
    }
}

void Path::InitializeParentFolder()
{
    if (path_.Empty()) {
        return;
    }

    int position = path_.Mutf8().find_last_of(PATH_DELIMITER);

    parent_folder_ = path_.Substr(0, position);
}

void Path::InitializeBasePath(std::string base_path)
{
    if (!base_path.empty() && base_path.back() == PATH_DELIMITER) {
        base_path_ = util::UString(base_path.substr(0, base_path.length() - 1), allocator_).View();
    } else {
        base_path_ = util::UString(base_path, allocator_).View();
    }

    is_relative_ = true;
}

Path::Path(const util::StringView &relative_path, const util::StringView &base_path, ArenaAllocator *allocator)
{
    Initializer(relative_path.Mutf8(), allocator);
    InitializeBasePath(base_path.Mutf8());
}

Path::Path(const std::string &absolute_path, ArenaAllocator *allocator)
{
    Initializer(absolute_path, allocator);
}

Path::Path(const std::string &relative_path, const std::string &base_path, ArenaAllocator *allocator)
{
    Initializer(relative_path, allocator);
    InitializeBasePath(base_path);
}

bool Path::IsRelative()
{
    return is_relative_;
}

bool Path::IsAbsolute()
{
    return !is_relative_;
}

const util::StringView &Path::GetPath() const
{
    return path_;
}

const util::StringView &Path::GetAbsolutePath() const
{
    return absolute_path_;
}

const util::StringView &Path::GetExtension() const
{
    return file_extension_;
}

const util::StringView &Path::GetFileName() const
{
    return file_name_;
}

const util::StringView &Path::GetParentFolder() const
{
    return parent_folder_;
}

const util::StringView &Path::GetAbsoluteParentFolder() const
{
    return absolute_parent_folder_;
}

}  // namespace panda::es2panda::util