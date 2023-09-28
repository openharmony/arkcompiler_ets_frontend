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

package com.ohos.migrator;

import com.ohos.migrator.staticTS.parser.StaticTSParser.CompilationUnitContext;
import com.ohos.migrator.staticTS.writer.StaticTSWriter;
import com.ohos.migrator.util.FileUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;


/**
 * Abstract transpiler class is base class for any source language transpilers.
 * Transpilation consists of 3 steps:
 * 1) Parse source file and create AST.
 * 2) Translate source AST to StaticTS AST.
 * 3) Write output file with StaticTS source code.
 */
public abstract class AbstractTranspiler implements Transpiler {
    protected List<File> sourceFiles;
    protected List<File> libFiles;
    protected List<File> outFiles;
    protected List<TranspileException> errorList;
    private String outDir = null;
    public AbstractTranspiler(List<File> src, List<File> libs, String outDir) {
        sourceFiles = src;
        libFiles = libs;
        outFiles = new LinkedList<>();
        errorList = new LinkedList<>();
        this.outDir = outDir;
    }

    public List<File> getOutFiles() { return outFiles; }

    public List<TranspileException> getErrorList(){
        return errorList;
    }

    public ResultCode transpile() {
        ResultCode transpileResult = ResultCode.OK;

        for (File f : sourceFiles) {
            try {
                transpileFile(f);
            } catch (TranspileException e) {
                // On parse errors, write commented-out
                // contents of input file to output file
                ResultCode result = e.getResult();
                if (result == ResultCode.ParseError)
                    writeUntranslatedFile(f);

                errorList.add(e);

                transpileResult = ResultCode.majorValue(result, transpileResult);
                if (Main.isStrictMode()) return transpileResult;
            }
            catch (Exception e) {
                StringBuilder sb = new StringBuilder(e.getClass().getName());
                sb.append(" while transpiling " + f.getPath() + " at:\n");

                for (StackTraceElement ste : e.getStackTrace())
                    sb.append(ste.toString()).append("\n");

                errorList.add(new TranspileException(ResultCode.TranspileError, sb.toString()));
                transpileResult = ResultCode.majorValue(ResultCode.TranspileError, transpileResult);
                if (Main.isStrictMode()) return transpileResult;
            }
        }

        return transpileResult;
    }

    protected abstract void transpileFile(File f) throws TranspileException;

    protected void write(CompilationUnitContext stsCU, File srcFile) {
        try {
            File outFile = getOutFile(srcFile);
            StaticTSWriter writer = new StaticTSWriter(outFile.getPath());
            writer.visit(stsCU);
            writer.close();

            if (outFile.exists()) outFiles.add(outFile);
        }
        catch (IOException e) {
            // TODO:
            System.err.println(e);
        }
    }

    private File getOutFile(File srcFile) {
        File outFile = new File(srcFile.getPath() + Main.STS_EXT);
        if (outDir != null) outFile = new File(outDir, outFile.getName());
        return outFile;
    }

    protected void writeUntranslatedFile(File srcFile) {
        File outFile = getOutFile(srcFile);
        try (FileWriter outFW = new FileWriter(outFile.getPath())){
            outFW.write("/* Untranslated source code:\n");
            FileUtils.copyFile(srcFile, outFW);
            outFW.write("*/\n");
        }
        catch (IOException ioe) {
            System.err.println(ioe);
        }
    }
    @Override
    public double getConversionRate() {
        return 0;
    }

    @Override
    public void migrateAPI(CompilationUnitContext arktsCU) {}
}
