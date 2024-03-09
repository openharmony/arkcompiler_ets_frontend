/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "arktsconfig.h"
#include "libpandabase/utils/json_builder.h"
#include "libpandabase/utils/json_parser.h"
#include "libpandabase/os/filesystem.h"
#include "util/language.h"
#include "generated/signatures.h"

#include <fstream>
#include <regex>
#include <sstream>
#include <system_error>

#ifndef ARKTSCONFIG_USE_FILESYSTEM
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#else
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif
#endif

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define CHECK(cond, ret, msg)                                   \
    if (!(cond)) {                                              \
        std::cerr << "ArkTsConfig error: " << msg << std::endl; \
        return ret;                                             \
    }

namespace ark::es2panda {

static bool IsAbsolute(const std::string &path)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    return !path.empty() && path[0] == '/';
#else
    return fs::path(path).is_absolute();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

std::string JoinPaths(const std::string &a, const std::string &b)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    return a + '/' + b;
#else
    return (fs::path(a) / b).string();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

std::string ParentPath(const std::string &path)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    auto pos = path.find('/');
    return pos == std::string::npos ? path : path.substr(0, pos);
#else
    return fs::path(path).parent_path().string();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

static std::string MakeAbsolute(const std::string &path, const std::string &base)
{
    return IsAbsolute(path) ? path : JoinPaths(base, path);
}

#ifdef ARKTSCONFIG_USE_FILESYSTEM

ArkTsConfig::Pattern::Pattern(std::string value, std::string base) : value_(std::move(value)), base_(std::move(base))
{
    ASSERT(fs::path(base_).is_absolute());
}

bool ArkTsConfig::Pattern::IsPattern() const
{
    return (value_.find('*') != std::string::npos) || (value_.find('?') != std::string::npos);
}

std::string ArkTsConfig::Pattern::GetSearchRoot() const
{
    fs::path relative;
    if (!IsPattern()) {
        relative = value_;
    } else {
        auto foundStar = value_.find_first_of('*');
        auto foundQuestion = value_.find_first_of('?');
        relative = value_.substr(0, std::min(foundStar, foundQuestion));
        relative = relative.parent_path();
    }
    return MakeAbsolute(relative.string(), base_);
}

bool ArkTsConfig::Pattern::Match(const std::string &path) const
{
    ASSERT(fs::path(path).is_absolute());
    fs::path value = fs::path(value_);
    std::string pattern = value.is_absolute() ? value.string() : (base_ / value).string();

    // Replace arktsconfig special symbols with regular expressions
    if (IsPattern()) {
        // '**' matches any directory nested to any level
        pattern = std::regex_replace(pattern, std::regex("\\*\\*/"), ".*");
        // '*' matches zero or more characters (excluding directory separators)
        pattern = std::regex_replace(pattern, std::regex("([^\\.])\\*"), "$1[^/]*");
        // '?' matches any one character (excluding directory separators)
        pattern = std::regex_replace(pattern, std::regex("\\?"), "[^/]");
    }
    if (!value.has_extension()) {
        // default extensions to match
        pattern += R"(.*(\.ts|\.d\.ts|\.ets)$)";
    }
    std::smatch m;
    auto res = std::regex_match(path, m, std::regex(pattern));
    return res;
}

#endif  // ARKTSCONFIG_USE_FILESYSTEM

#ifdef ARKTSCONFIG_USE_FILESYSTEM
static std::string ResolveConfigLocation(const std::string &relPath, const std::string &base)
{
    auto resolvedPath = MakeAbsolute(relPath, base);
    auto newBase = base;
    while (!fs::exists(resolvedPath)) {
        resolvedPath = MakeAbsolute(relPath, JoinPaths(newBase, "node_modules"));
        if (newBase == ParentPath(newBase)) {
            return "";
        }
        newBase = ParentPath(newBase);
    }
    return resolvedPath;
}
#endif  // ARKTSCONFIG_USE_FILESYSTEM

static std::string ValidDynamicLanguages()
{
    JsonArrayBuilder builder;
    for (auto &l : Language::All()) {
        if (l.IsDynamic()) {
            builder.Add(l.ToString());
        }
    }
    return std::move(builder).Build();
}

bool ArkTsConfig::Parse()
{
    static const std::string BASE_URL = "baseUrl";
    static const std::string COMPILER_OPTIONS = "compilerOptions";
    static const std::string EXCLUDE = "exclude";
    static const std::string EXTENDS = "extends";
    static const std::string FILES = "files";
    static const std::string INCLUDE = "include";
    static const std::string OUT_DIR = "outDir";
    static const std::string PATHS = "paths";
    static const std::string DYNAMIC_PATHS = "dynamicPaths";
    static const std::string ROOT_DIR = "rootDir";
    static const std::string LANGUAGE = "language";
    static const std::string HAS_DECL = "hasDecl";

    ASSERT(!isParsed_);
    isParsed_ = true;
    auto arktsConfigDir = ParentPath(ark::os::GetAbsolutePath(configPath_));

    // Read input
    std::ifstream inputStream(configPath_);
    CHECK(!inputStream.fail(), false, "Failed to open file: " << configPath_);
    std::stringstream ss;
    ss << inputStream.rdbuf();
    std::string tsConfigSource = ss.str();
    inputStream.close();

    // Parse json
    auto arktsConfig = std::make_unique<JsonObject>(tsConfigSource);
    CHECK(arktsConfig->IsValid(), false, "ArkTsConfig is not valid json");

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "extends"
    auto extends = arktsConfig->GetValue<JsonObject::StringT>(EXTENDS);
    if (extends != nullptr) {
        auto basePath = ResolveConfigLocation(*extends, arktsConfigDir);
        CHECK(!basePath.empty(), false, "Can't resolve config path: " << *extends);
        auto base = ArkTsConfig(basePath);
        CHECK(base.Parse(), false, "Failed to parse base config: " << *extends);
        Inherit(base);
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    // Parse "baseUrl", "outDir", "rootDir"
    auto compilerOptions = arktsConfig->GetValue<JsonObject::JsonObjPointer>(COMPILER_OPTIONS);
    auto parseRelDir = [&](std::string &dst, const std::string &key) {
        if (compilerOptions != nullptr) {
            auto path = compilerOptions->get()->GetValue<JsonObject::StringT>(key);
            dst = ((path != nullptr) ? *path : "");
        }
        dst = MakeAbsolute(dst, arktsConfigDir);
    };
    parseRelDir(baseUrl_, BASE_URL);
    parseRelDir(outDir_, OUT_DIR);
    parseRelDir(rootDir_, ROOT_DIR);

    // Parse "paths"
    if (compilerOptions != nullptr) {
        auto paths = compilerOptions->get()->GetValue<JsonObject::JsonObjPointer>(PATHS);
        if (paths != nullptr) {
            for (size_t keyIdx = 0; keyIdx < paths->get()->GetSize(); ++keyIdx) {
                auto &key = paths->get()->GetKeyByIndex(keyIdx);
                if (paths_.count(key) == 0U) {
                    paths_.insert({key, {}});
                }

                auto values = paths->get()->GetValue<JsonObject::ArrayT>(key);
                CHECK(values, false, "Invalid value for 'path' with key '" << key << "'");
                CHECK(!values->empty(), false, "Substitutions for pattern '" << key << "' shouldn't be an empty array");
                for (auto &v : *values) {
                    auto p = *v.Get<JsonObject::StringT>();
                    paths_[key].emplace_back(MakeAbsolute(p, baseUrl_));
                }
            }
        }

        auto dynamicPaths = compilerOptions->get()->GetValue<JsonObject::JsonObjPointer>(DYNAMIC_PATHS);
        if (dynamicPaths != nullptr) {
            for (size_t keyIdx = 0; keyIdx < dynamicPaths->get()->GetSize(); ++keyIdx) {
                auto &key = dynamicPaths->get()->GetKeyByIndex(keyIdx);
                auto data = dynamicPaths->get()->GetValue<JsonObject::JsonObjPointer>(key);
                CHECK(data, false, "Invalid value for for dynamic path with key '" << key << "'");

                auto langValue = data->get()->GetValue<JsonObject::StringT>(LANGUAGE);
                CHECK(langValue, false, "Invalid 'language' value for dynamic path with key '" << key << "'");

                auto lang = Language::FromString(*langValue);
                CHECK((lang && lang->IsDynamic()), false,
                      "Invalid 'language' value for dynamic path with key '" << key << "'. Should be one of "
                                                                             << ValidDynamicLanguages());

                CHECK(compiler::Signatures::Dynamic::IsSupported(*lang), false,
                      "Interoperability with language '" << lang->ToString() << "' is not supported");

                auto hasDeclValue = data->get()->GetValue<JsonObject::BoolT>(HAS_DECL);
                CHECK(hasDeclValue, false, "Invalid 'hasDecl' value for dynamic path with key '" << key << "'");

                auto normalizedKey = ark::os::NormalizePath(key);
                auto res = dynamicPaths_.insert({normalizedKey, DynamicImportData(*lang, *hasDeclValue)});
                CHECK(res.second, false, "Duplicated dynamic path '" << key << "' for key '" << key << "'");
            }
        }
    }

    // Parse "files"
    auto files = arktsConfig->GetValue<JsonObject::ArrayT>(FILES);
    if (files != nullptr) {
        files_ = {};
        CHECK(!files->empty(), false, "The 'files' list in config file is empty");
        for (auto &f : *files) {
            files_.emplace_back(MakeAbsolute(*f.Get<JsonObject::StringT>(), arktsConfigDir));
        }
    }

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "include"
    auto include = arktsConfig->GetValue<JsonObject::ArrayT>(INCLUDE);
    if (include != nullptr) {
        include_ = {};
        CHECK(!include->empty(), false, "The 'include' list in config file is empty");
        for (auto &i : *include) {
            include_.emplace_back(*i.Get<JsonObject::StringT>(), arktsConfigDir);
        }
    }
    // Parse "exclude"
    auto exclude = arktsConfig->GetValue<JsonObject::ArrayT>(EXCLUDE);
    if (exclude != nullptr) {
        exclude_ = {};
        CHECK(!exclude->empty(), false, "The 'exclude' list in config file is empty");
        for (auto &e : *exclude) {
            exclude_.emplace_back(*e.Get<JsonObject::StringT>(), arktsConfigDir);
        }
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    return true;
}

void ArkTsConfig::Inherit(const ArkTsConfig &base)
{
    baseUrl_ = base.baseUrl_;
    outDir_ = base.outDir_;
    rootDir_ = base.rootDir_;
    paths_ = base.paths_;
    files_ = base.files_;
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    include_ = base.include_;
    exclude_ = base.exclude_;
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

// Remove '/' and '*' from the end of path
static std::string TrimPath(const std::string &path)
{
    std::string trimmedPath = path;
    while (!trimmedPath.empty() && (trimmedPath.back() == '*' || trimmedPath.back() == '/')) {
        trimmedPath.pop_back();
    }
    return trimmedPath;
}

std::optional<std::string> ArkTsConfig::ResolvePath(const std::string &path) const
{
    for (const auto &[alias, paths] : paths_) {
        auto trimmedAlias = TrimPath(alias);
        size_t pos = path.rfind(trimmedAlias, 0);
        if (pos == 0) {
            std::string resolved = path;
            // NOTE(ivagin): arktsconfig contains array of paths for each prefix, for now just get first one
            std::string newPrefix = TrimPath(paths[0]);
            resolved.replace(pos, trimmedAlias.length(), newPrefix);
            return resolved;
        }
    }
    return std::nullopt;
}

#ifdef ARKTSCONFIG_USE_FILESYSTEM
static bool MatchExcludes(const fs::path &path, const std::vector<ArkTsConfig::Pattern> &excludes)
{
    for (auto &e : excludes) {
        if (e.Match(path.string())) {
            return true;
        }
    }
    return false;
}

static std::vector<fs::path> GetSourceList(const std::shared_ptr<ArkTsConfig> &arktsConfig)
{
    auto includes = arktsConfig->Include();
    auto excludes = arktsConfig->Exclude();
    auto files = arktsConfig->Files();

    // If "files" and "includes" are empty - include everything from tsconfig root
    auto configDir = fs::absolute(fs::path(arktsConfig->ConfigPath())).parent_path();
    if (files.empty() && includes.empty()) {
        includes = {ArkTsConfig::Pattern("**/*", configDir.string())};
    }
    // If outDir in not default add it into exclude
    if (!fs::equivalent(arktsConfig->OutDir(), configDir)) {
        excludes.emplace_back("**/*", arktsConfig->OutDir());
    }

    // Collect "files"
    std::vector<fs::path> sourceList;
    for (auto &f : files) {
        CHECK(fs::exists(f) && fs::path(f).has_filename(), {}, "No such file: " << f);
        sourceList.emplace_back(f);
    }

    // Collect "include"
    // TSC traverses folders for sources starting from 'include' rather than from 'rootDir', so we do the same
    for (auto &include : includes) {
        auto traverseRoot = fs::path(include.GetSearchRoot());
        if (!fs::exists(traverseRoot)) {
            continue;
        }
        if (!fs::is_directory(traverseRoot)) {
            if (include.Match(traverseRoot.string()) && !MatchExcludes(traverseRoot, excludes)) {
                sourceList.emplace_back(traverseRoot);
            }
            continue;
        }
        for (const auto &dirEntry : fs::recursive_directory_iterator(traverseRoot)) {
            if (include.Match(dirEntry.path().string()) && !MatchExcludes(dirEntry, excludes)) {
                sourceList.emplace_back(dirEntry);
            }
        }
    }
    return sourceList;
}

// Analogue of 'std::filesystem::relative()'
// Example: Relative("/a/b/c", "/a/b") returns "c"
static fs::path Relative(const fs::path &src, const fs::path &base)
{
    fs::path tmpPath = src;
    fs::path relPath;
    while (!fs::equivalent(tmpPath, base)) {
        relPath = relPath.empty() ? tmpPath.filename() : tmpPath.filename() / relPath;
        if (tmpPath == tmpPath.parent_path()) {
            return fs::path();
        }
        tmpPath = tmpPath.parent_path();
    }
    return relPath;
}

// Compute path to destination file and create subfolders
static fs::path ComputeDestination(const fs::path &src, const fs::path &rootDir, const fs::path &outDir)
{
    auto rel = Relative(src, rootDir);
    CHECK(!rel.empty(), {}, rootDir << " is not root directory for " << src);
    auto dst = outDir / rel;
    fs::create_directories(dst.parent_path());
    return dst.replace_extension("abc");
}

std::vector<std::pair<std::string, std::string>> FindProjectSources(const std::shared_ptr<ArkTsConfig> &arktsConfig)
{
    auto sourceFiles = GetSourceList(arktsConfig);
    std::vector<std::pair<std::string, std::string>> compilationList;
    for (auto &src : sourceFiles) {
        auto dst = ComputeDestination(src, arktsConfig->RootDir(), arktsConfig->OutDir());
        CHECK(!dst.empty(), {}, "Invalid destination file");
        compilationList.emplace_back(src.string(), dst.string());
    }

    return compilationList;
}
#else
std::vector<std::pair<std::string, std::string>> FindProjectSources(
    [[maybe_unused]] const std::shared_ptr<ArkTsConfig> &arkts_config)
{
    ASSERT(false);
    return {};
}
#endif  // ARKTSCONFIG_USE_FILESYSTEM

}  // namespace ark::es2panda
