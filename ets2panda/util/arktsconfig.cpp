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

namespace ark::es2panda {

template <class... Ts>
static bool Check(bool cond, const Ts &...msgs)
{
    if (!cond) {
        ((std::cerr << "ArkTsConfig error: ") << ... << msgs);
        std::cerr << '\n';
        return false;
    }

    return true;
}

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
        pattern += R"(.*(\.ts|\.d\.ts|\.sts)$)";
    }
    std::smatch m;
    auto res = std::regex_match(path, m, std::regex(pattern));
    return res;
}

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

static std::optional<ArkTsConfig> ParseExtends(const std::string &configPath, const std::string &extends,
                                               const std::string &configDir)
{
    auto basePath = ResolveConfigLocation(extends, configDir);
    if (!Check(!basePath.empty(), "Can't resolve config path: ", extends)) {
        return {};
    }

    if (!Check(basePath != configPath, "Encountered cyclic import in 'extends' field")) {
        return {};
    }

    auto base = ArkTsConfig(basePath);
    if (!Check(base.Parse(), "Failed to parse base config: ", extends)) {
        return {};
    }

    return base;
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

template <class PathsMap>
static bool ParsePaths(const JsonObject::JsonObjPointer *options, PathsMap &pathsMap, const std::string &baseUrl)
{
    if (options == nullptr) {
        return true;
    }

    auto paths = options->get()->GetValue<JsonObject::JsonObjPointer>("paths");
    if (paths == nullptr) {
        return true;
    }

    for (size_t keyIdx = 0; keyIdx < paths->get()->GetSize(); ++keyIdx) {
        auto &key = paths->get()->GetKeyByIndex(keyIdx);
        if (pathsMap.count(key) == 0U) {
            pathsMap.insert({key, {}});
        }

        auto values = paths->get()->GetValue<JsonObject::ArrayT>(key);
        if (!Check(values, "Invalid value for 'path' with key '", key, "'")) {
            return false;
        }

        if (!Check(!values->empty(), "Substitutions for pattern '", key, "' shouldn't be an empty array")) {
            return false;
        }

        for (auto &v : *values) {
            auto p = *v.Get<JsonObject::StringT>();
            pathsMap[key].emplace_back(MakeAbsolute(p, baseUrl));
        }
    }

    return true;
}

template <class PathsMap>
static bool ParseDynamicPaths(const JsonObject::JsonObjPointer *options, PathsMap &dynamicPathsMap)
{
    static const std::string LANGUAGE = "language";
    static const std::string HAS_DECL = "hasDecl";

    if (options == nullptr) {
        return true;
    }

    auto dynamicPaths = options->get()->GetValue<JsonObject::JsonObjPointer>("dynamicPaths");
    if (dynamicPaths == nullptr) {
        return true;
    }

    for (size_t keyIdx = 0; keyIdx < dynamicPaths->get()->GetSize(); ++keyIdx) {
        auto &key = dynamicPaths->get()->GetKeyByIndex(keyIdx);
        auto data = dynamicPaths->get()->GetValue<JsonObject::JsonObjPointer>(key);
        if (!Check(data != nullptr, "Invalid value for for dynamic path with key '", key, "'")) {
            return false;
        }

        auto langValue = data->get()->GetValue<JsonObject::StringT>(LANGUAGE);
        if (!Check(langValue != nullptr, "Invalid '", LANGUAGE, "' value for dynamic path with key '", key, "'")) {
            return false;
        }

        auto lang = Language::FromString(*langValue);
        if (!Check(lang && lang->IsDynamic(), "Invalid '", LANGUAGE, "' value for dynamic path with key '", key,
                   "'. Should be one of ", ValidDynamicLanguages())) {
            return false;
        }

        if (!Check(compiler::Signatures::Dynamic::IsSupported(*lang), "Interoperability with language '",
                   lang->ToString(), "' is not supported")) {
            return false;
        }

        auto hasDeclValue = data->get()->GetValue<JsonObject::BoolT>(HAS_DECL);
        if (!Check(hasDeclValue != nullptr, "Invalid '", HAS_DECL, "' value for dynamic path with key '", key, "'")) {
            return false;
        }

        auto normalizedKey = ark::os::NormalizePath(key);
        auto res = dynamicPathsMap.insert({normalizedKey, ArkTsConfig::DynamicImportData(*lang, *hasDeclValue)});
        if (!Check(res.second, "Duplicated dynamic path '", key, "' for key '", key, "'")) {
            return false;
        }
    }

    return true;
}

template <class Collection, class Function>
static bool ParseCollection(const JsonObject *config, Collection &out, const std::string &target,
                            Function &&constructor)
{
    auto *arr = config->GetValue<JsonObject::ArrayT>(target);
    if (!Check(arr != nullptr, "'", target, "'", " must be an array")) {
        return false;
    }

    out = {};
    if (!Check(!arr->empty(), "The '", target, "' list in config file is empty")) {
        return false;
    }

    for (auto &i : *arr) {
        out.emplace_back(constructor(*i.Get<JsonObject::StringT>()));
    }

    return true;
}

static std::optional<std::string> ReadConfig(const std::string &path)
{
    std::ifstream inputStream(path);
    if (!Check(!inputStream.fail(), "Failed to open file: ", path)) {
        return {};
    }

    std::stringstream ss;
    ss << inputStream.rdbuf();
    return ss.str();
}

static void ParseRelDir(std::string &dst, const std::string &key, const JsonObject::JsonObjPointer *options,
                        const std::string &configDir)
{
    if (options != nullptr) {
        auto path = options->get()->GetValue<JsonObject::StringT>(key);
        dst = ((path != nullptr) ? *path : "");
    }

    dst = MakeAbsolute(dst, configDir);
}

bool ArkTsConfig::Parse()
{
    ASSERT(!isParsed_);
    isParsed_ = true;
    auto arktsConfigDir = ParentPath(ark::os::GetAbsolutePath(configPath_));

    // Read input
    auto tsConfigSource = ReadConfig(configPath_);
    if (!tsConfigSource) {
        return false;
    }

    // Parse json
    auto arktsConfig = std::make_unique<JsonObject>(*tsConfigSource);
    if (!Check(arktsConfig->IsValid(), "ArkTsConfig is not valid json")) {
        return false;
    }

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "extends"
    if (arktsConfig->HasKey(EXTENDS)) {
        auto *extends = arktsConfig->GetValue<JsonObject::StringT>(EXTENDS);
        if (!Check(extends != nullptr, "'", EXTENDS, "'", " must be a string")) {
            return false;
        }
        const auto &base = ParseExtends(configPath_, *extends, arktsConfigDir);
        if (!base.has_value()) {
            return false;
        }
        Inherit(*base);
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    auto compilerOptions = arktsConfig->GetValue<JsonObject::JsonObjPointer>(COMPILER_OPTIONS);

    // Parse "baseUrl", "outDir", "rootDir"
    ParseRelDir(baseUrl_, BASE_URL, compilerOptions, arktsConfigDir);
    ParseRelDir(outDir_, OUT_DIR, compilerOptions, arktsConfigDir);
    ParseRelDir(rootDir_, ROOT_DIR, compilerOptions, arktsConfigDir);

    // Parse "paths"
    if (!ParsePaths(compilerOptions, paths_, baseUrl_) || !ParseDynamicPaths(compilerOptions, dynamicPaths_)) {
        return false;
    }

    // Parse "files"
    auto concatPath = [&arktsConfigDir](const auto &val) { return MakeAbsolute(val, arktsConfigDir); };
    if (arktsConfig->HasKey(FILES) && !ParseCollection(arktsConfig.get(), files_, FILES, concatPath)) {
        return false;
    }

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "include" and "exclude"
    auto consPattern = [&arktsConfigDir](const auto &val) { return Pattern {val, arktsConfigDir}; };
    if (arktsConfig->HasKey(INCLUDE) && !ParseCollection(arktsConfig.get(), include_, INCLUDE, consPattern)) {
        return false;
    }
    if (arktsConfig->HasKey(EXCLUDE) && !ParseCollection(arktsConfig.get(), exclude_, EXCLUDE, consPattern)) {
        return false;
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
        if (!Check(fs::exists(f) && fs::path(f).has_filename(), "No such file: ", f)) {
            return {};
        }

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
    if (!Check(!rel.empty(), rootDir, " is not root directory for ", src)) {
        return {};
    }

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
        if (!Check(!dst.empty(), "Invalid destination file")) {
            return {};
        }

        compilationList.emplace_back(src.string(), dst.string());
    }

    return compilationList;
}
#else
std::vector<std::pair<std::string, std::string>> FindProjectSources(
    // CC-OFFNXT(G.FMT.06-CPP) project code style
    [[maybe_unused]] const std::shared_ptr<ArkTsConfig> &arkts_config)
{
    ASSERT(false);
    return {};
}
#endif  // ARKTSCONFIG_USE_FILESYSTEM

}  // namespace ark::es2panda
