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

package com.ohos.migrator.java;

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.TranspileException;
import com.ohos.migrator.util.FileUtils;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.compiler.IProblem;
import org.eclipse.jdt.core.dom.AST;
import org.eclipse.jdt.core.dom.ASTParser;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.eclipse.jdt.core.dom.PackageDeclaration;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;

/**
 * Parses Java source file and returns AST representing the source code.
 */
public class JavaParser {
    private char[] source;
    private File sourceFile;
    private static Map<File, String> packagePaths = new HashMap<>();

    private static String[] sourcepathEntries = null;
    private String[] classpathEntries = null;

    /*
     migrator purpose is to translate Java8 sources (with some features of Java9)
     into Static TS, so use deprecated value to enable Java9
     */
    public static final int inputLanguageLevel = AST.JLS9;
    public static final String compliance = JavaCore.VERSION_9;

    /**
     * Create a Java parser.
     *
     * @param sourceFile Java source file to be parsed.
     * @param sourceFiles List of Java source files whose paths will be used to configure
     *                    parser's 'sourcepaths' setting.
     * @param classpaths  List of paths to jar files or directories with '.class' files.
    */
    public JavaParser(File sourceFile, List<File> sourceFiles, List<File> classpaths, boolean noxrefs) throws IOException {
        this(sourceFile);

        // Compute reference source paths once, unless
        // explicitly prohibited by command-line option
        if (!noxrefs && sourcepathEntries == null)
            setSourcepathEntries(sourceFiles);
        
        setClasspathEntries(classpaths);
    }

    public JavaParser(File sourceFile) throws IOException {
        this.sourceFile = sourceFile;
        this.source = FileUtils.readFileToCharArray(sourceFile);
    }

    public JavaParser(char[] source) {
        this.source = source;
    }

    public char[] getJavaSource() { return source; }

    private static String getPackagePath(File file) {
        // If already processed this file, return the result from cache.
        if (packagePaths.containsKey(file)) {
            return packagePaths.get(file);
        }

        String packagePath = null;
        Exception caughtEx = null;

        // Parse source file to retrieve declared package name, if any.
        try {
            // This call may throw IOException, therefore we place it at the top
            // to avoid any further action in case it in fact throws.
            char[] sourceCode = FileUtils.readFileToCharArray(file);

            ASTParser parser = JavaParser.createASTParser(ASTParser.K_COMPILATION_UNIT);
            parser.setUnitName(file.getPath());
            parser.setSource(sourceCode);

            // Set focal position to optimize parsing process, since we
            // only care about package name.
            parser.setFocalPosition(0);

            CompilationUnit cu = createCU(parser);

            if (cu != null) {
                PackageDeclaration pkg = cu.getPackage();

                if (pkg != null) {
                    packagePath = pkg.getName().getFullyQualifiedName();
                    packagePath = packagePath.replace('.', File.separatorChar);
                }
            }
        } catch (Exception ex) {
            caughtEx = ex;
        } finally {
            // Warn if in verbose mode and package path is null
            if (packagePath == null && Main.isVerboseMode()) {
                String warning = "[warning] Failed to get package path for file " + file.getPath();
                if (caughtEx != null) warning += " due to " + caughtEx.getMessage();
                System.err.println(warning);
            }

            // Store result in cache to avoid recomputing package path
            // for the same file later and if it failed or returned null as expected
            // (no package declaration in file) the first time.
            packagePaths.put(file, packagePath);
        }

        return packagePath;
    }

    private static void setSourcepathEntries(List<File> sourceFiles) {
        Set<String> filePaths = new HashSet<>();

        for (File file : sourceFiles) {
            // ASTParser accepts only directories where reference sources
            // are located. Thus, store the parent of each source file path.
            String pkg = getPackagePath(file);
            String path = file.getAbsoluteFile().getParent();

            if (pkg != null && path != null && path.endsWith(pkg)) {
                // Remove package path from source path as ASTParser accounts
                // for package declaration in source files.
                path = path.substring(0, path.length() - pkg.length() - 1);
            }

            filePaths.add(path);
        }

        if (!filePaths.isEmpty()) {
            sourcepathEntries = filePaths.toArray(new String[0]);
        }
    }

    private void setClasspathEntries(List<File> classpaths) {
        Set<String> classFiles = new HashSet<>();

        for (File file : classpaths) {
            if(!file.exists()) continue;

            // Note: Eclipse's parser requires absolute path for classpath settings.
            String path = file.getAbsolutePath();
            classFiles.add(path);
        }

        if (!classFiles.isEmpty()) {
            classpathEntries = classFiles.toArray(new String[0]);
        }
    }

    private static ASTParser createASTParser(int kind) {
        ASTParser parser = ASTParser.newParser(inputLanguageLevel);
        Map<String, String> options = JavaCore.getOptions();
        JavaCore.setComplianceOptions(compliance, options);
        parser.setCompilerOptions(options);
        parser.setKind(kind);

        return parser;
    }

    private static CompilationUnit createCU(ASTParser parser) throws JavaParserException {
        CompilationUnit cu = null;
        try {
            cu = (CompilationUnit) parser.createAST(null);
        }
        catch (Exception e) {
            throw new JavaParserException(e);
        }

        if (cu == null) throw new JavaParserException("unknown Java parsing error");

        return cu;
    }
    public CompilationUnit parse() throws JavaParserException {
        ASTParser parser = createASTParser(ASTParser.K_COMPILATION_UNIT);
        parser.setSource(source);
        parser.setResolveBindings(true);

        // Set recovery options.
        parser.setBindingsRecovery(true);
        parser.setStatementsRecovery(true);

        // For the correct binding resolving, parser requires to have the Java model set up.
        // For this, set the environment and Unit name properties.
        // TODO: Investigate whether we need to set 'includeRunningVMBootclasspath' to another value.
        boolean includeRunningVMBootclasspath = true;
        parser.setEnvironment(classpathEntries, sourcepathEntries, null, includeRunningVMBootclasspath);
        parser.setUnitName(sourceFile.getPath());

        CompilationUnit cu = createCU(parser);

        // In strict mode, terminate on syntax or semantic errors;
        // otherwise, report them and continue.
        for (IProblem problem : cu.getProblems()) {
            if (problem.isError()) {
                if (Main.isStrictMode())
                    throw new JavaParserException(cu.getProblems());
                else
                    Main.addError(ResultCode.ParseError, buildErrorMessage(problem));
            }
        }

        return cu;
    }

    public static String buildErrorMessage(IProblem problem) {
        StringBuilder sb = new StringBuilder();
        int lineNumber = problem.getSourceLineNumber();
        String fileName = String.valueOf(problem.getOriginatingFileName());

        String pos = fileName + "(" + lineNumber + "): ";
        sb.append(pos).append(problem.getMessage());

        return sb.toString();
    }
}
