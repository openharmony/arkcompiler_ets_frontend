/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.kotlin;

import com.ohos.migrator.AbstractTranspiler;
import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.TranspileException;
import com.ohos.migrator.staticTS.parser.StaticTSParser.CompilationUnitContext;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.util.Disposer;
import com.ohos.migrator.util.FileUtils;
import org.jetbrains.kotlin.analyzer.AnalysisResult;
import org.jetbrains.kotlin.cli.common.CLIConfigurationKeys;
import org.jetbrains.kotlin.cli.common.messages.AnalyzerWithCompilerReport;
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSeverity;
import org.jetbrains.kotlin.cli.common.messages.CompilerMessageSourceLocation;
import org.jetbrains.kotlin.cli.common.messages.MessageCollector;
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles;
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment;
import org.jetbrains.kotlin.cli.jvm.compiler.NoScopeRecordCliBindingTrace;
import org.jetbrains.kotlin.cli.jvm.compiler.TopDownAnalyzerFacadeForJVM;
import org.jetbrains.kotlin.cli.jvm.config.JvmContentRootsKt;
import org.jetbrains.kotlin.config.CommonConfigurationKeys;
import org.jetbrains.kotlin.config.CompilerConfiguration;
import org.jetbrains.kotlin.metadata.jvm.deserialization.JvmProtoBufUtil;
import org.jetbrains.kotlin.psi.KtFile;
import org.jetbrains.kotlin.utils.PathUtil;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.*;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Kotlin to StaticTS transpiler class inherited from AbstractTranspiler class.
 * Transpilation consists of 4 steps:
 * 1) Parse Kotlin source files and create Kotlin AST.
 * 2) Perform semantic analysis and code diagnostics, build semantic model.
 * 3) Translate Kotlin AST to StaticTS AST.
 * 4) Write output file with StaticTS source code.
 */
public class KotlinTranspiler extends AbstractTranspiler {

    CompilerConfiguration configuration;
    KotlinCoreEnvironment environment;

    String MANIFEST_IMPLEMENTATION_TITLE = "Implementation-Title";

    static {
        org.jetbrains.kotlin.cli.common.environment.UtilKt.setIdeaIoUseFallback();
    }

    public KotlinTranspiler(List<File> src, List<File> libs, String outDir) {
        super(src, libs, outDir);

        configuration = createConfiguration();
        configureCompiler();
        environment = createEnvironment();
    }

    private static class ErrorMessageCollector implements MessageCollector {
        private List<String> errors = new LinkedList<>();

        @Override
        public void clear() {
            errors.clear();
        }

        @Override
        public boolean hasErrors() {
            return !errors.isEmpty();
        }

        @Override
        public void report(CompilerMessageSeverity severity, String message, CompilerMessageSourceLocation location) {
            if (severity.isError()) {
                String pos = (location == null || location.getPath() == null)
                        ? "" : location.getPath() + ": (" + location.getLine() + ", " + location.getColumn() + ") ";
                errors.add("[error] " + pos + message);
            }
        }

        public List<String> getErrors() {
            return errors;
        }
    }

    public CompilerConfiguration createConfiguration() {
        CompilerConfiguration compilerConfiguration = new CompilerConfiguration();
        compilerConfiguration.put(CommonConfigurationKeys.MODULE_NAME, JvmProtoBufUtil.DEFAULT_MODULE_NAME);

        ErrorMessageCollector errorCollector = new ErrorMessageCollector();
        compilerConfiguration.put(CLIConfigurationKeys.MESSAGE_COLLECTOR_KEY, errorCollector);

        return compilerConfiguration;
    }

    public KotlinCoreEnvironment createEnvironment() {
        Disposable disposable = Disposer.newDisposable();
        return KotlinCoreEnvironment.createForProduction(
                disposable,
                configuration,
                EnvironmentConfigFiles.JVM_CONFIG_FILES
        );
    }

    private void configureCompiler() {
        // Add user-defined classpaths.
        JvmContentRootsKt.addJvmClasspathRoots(configuration, libFiles);

        // Configure kotlin libraries.
        JvmContentRootsKt.addJvmClasspathRoots(configuration, getKotlinJars());

        // Configure JDK classpaths.
        JvmContentRootsKt.configureJdkClasspathRoots(configuration);
    }

    private List<File> getKotlinJars() {
        // NOTE: The Kotlin libraries are currently placed in the same
        // directory as the application jar.
        File[] jarFiles = null;
        try {
            jarFiles = FileUtils.getMigratorLibDir().listFiles(file -> isBuiltinKotlinJar(getManifestImplementationTitle(file)));
        } catch (URISyntaxException e1)
        {}

        /* Just to be safe */
        if (jarFiles == null) {
            return new ArrayList<>();
        }
        return Arrays.asList(jarFiles);
    }

    private boolean isBuiltinKotlinJar(String name) {
        return (name != null &&
                (name.startsWith(PathUtil.KOTLIN_JAVA_STDLIB_NAME) || // kotlin-stdlib
                name.equals(PathUtil.KOTLIN_TEST_NAME) || // kotlin-test
                name.equals(PathUtil.KOTLIN_JAVA_REFLECT_NAME) || // kotlin-reflect
                name.equals(PathUtil.KOTLIN_JAVA_SCRIPT_RUNTIME_NAME))); // kotlin-script-runtime
    }

    private String getManifestImplementationTitle(File file){
        try {
            JarFile jarFile = new JarFile(file);
            Manifest manifest = jarFile.getManifest();

            if (manifest == null) {
                return null;
            }
            return manifest.getMainAttributes().getValue(MANIFEST_IMPLEMENTATION_TITLE);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public ResultCode transpile() {
        ResultCode transpileResult = ResultCode.OK;

        try {
            Map<File, KtFile> sourceToKotlin = parse();
            AnalysisResult analysisResult = analyze(sourceToKotlin.values());

            for (Map.Entry<File, KtFile> entry : sourceToKotlin.entrySet()) {
                CompilationUnitContext stsCU = transform(entry.getValue(), entry.getKey(), analysisResult);
                write(stsCU, entry.getKey());
            }
        } catch (Exception e) {
            transpileResult = ResultCode.TranspileError;
            errorList.add(new TranspileException(transpileResult, e));
        }

        return transpileResult;
    }

    private Map<File, KtFile> parse() {
        Map<File, KtFile> sourceToKotlin = new LinkedHashMap<>();

        for(File srcFile : sourceFiles) {
            try {
                KotlinParser parser = new KotlinParser(srcFile, environment);
                sourceToKotlin.put(srcFile, parser.parse());
            } catch (IOException e) {
                errorList.add(new TranspileException(ResultCode.InputError, e));
            } catch (KotlinParserException e) {
                errorList.add(new TranspileException(ResultCode.ParseError, e));
            }
        }

        return sourceToKotlin;
    }

    private AnalysisResult analyze(Collection<KtFile> ktFiles) {
        AnalyzerWithCompilerReport analyzer = new AnalyzerWithCompilerReport(configuration);
        analyzer.analyzeAndReport(ktFiles, () ->
                TopDownAnalyzerFacadeForJVM.analyzeFilesWithJavaIntegration(
                        environment.getProject(),
                        ktFiles,
                        new NoScopeRecordCliBindingTrace(),
                        configuration,
                        environment::createPackagePartProvider)
        );

        // For now, print all error messages to console.
        ErrorMessageCollector errorCollector = (ErrorMessageCollector) configuration.get(CLIConfigurationKeys.MESSAGE_COLLECTOR_KEY);
        for(String err : errorCollector.getErrors()) {
            System.err.println(err);
        }

        return analyzer.getAnalysisResult();
    }

    private CompilationUnitContext transform(KtFile ktFile, File srcFile, AnalysisResult analysisResult) {
        KotlinTransformer transformer = new KotlinTransformer(ktFile, srcFile, analysisResult);
        return transformer.transform();
    }

    @Override
    protected void transpileFile(File f) throws TranspileException { }

    @Override
    public double getConversionRate() {
        // TODO: Update as Kotlin transpilation is implemented.
        return 0.;
    }
}
