/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { Type, ArkMethod, ArkAssignStmt, Scene, ArkInstanceFieldRef, FunctionType, ClassType, MethodSignature } from "arkanalyzer/lib";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";
import { ArkFile, Language } from 'arkanalyzer/lib/core/model/ArkFile';


const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropJSModifyPropertyCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: 'the layout of objects that may be passed from 1.2 should not be modified'
};

const RULE_ID = 'interop-change-static-object-layout';

export class InteropJSModifyPropertyCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];


    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check
        }
        return [matchBuildCb];
    }

    public check = (scene: Scene) => {
        const targetMethods: Map<MethodSignature, boolean[]> = new Map();
        scene.getFiles().forEach(file => {
            file.getImportInfos().forEach(importInfo => {
                const exportInfo = importInfo.getLazyExportInfo();
                if (exportInfo === null) {
                    return;
                }
                const arkExport = exportInfo.getArkExport();
                if (arkExport === null || arkExport === undefined) {
                    return;
                }
                if (arkExport instanceof ArkMethod && arkExport.getLanguage() === Language.JAVASCRIPT) {
                    const idxFlag = new Array(arkExport.getParameters().length).fill(false);
                    targetMethods.set(arkExport.getSignature(), idxFlag);
                }
            });

            for (let clazz of file.getClasses()) {
                for (let mtd of clazz.getMethods()) {
                    this.findCallsite(mtd, targetMethods, scene);
                }
            }
            for (let namespace of file.getAllNamespacesUnderThisFile()) {
                for (let clazz of namespace.getClasses()) {
                    for (let mtd of clazz.getMethods()) {
                        this.findCallsite(mtd, targetMethods, scene);
                    }
                }
            }
        });

        targetMethods.forEach((idxFlag, methodSig) => {
            const method = scene.getMethod(methodSig);
            if (!method) {
                return logger.error(`cannot find ark method by method sig: ${methodSig.toString()}`);
            }
            const targetParams = method.getParameterInstances().filter((_, idx) => idxFlag[idx]);
            const stmts = method.getBody()?.getCfg().getStmts() ?? [];
            for (const stmt of stmts) {
                if (!(stmt instanceof ArkAssignStmt)) {
                    continue;
                }
                const leftOp = stmt.getLeftOp();
                if (!(leftOp instanceof ArkInstanceFieldRef)) {
                    continue;
                }
                if (targetParams.includes(leftOp.getBase())) {
                    const line = stmt.getOriginPositionInfo().getLineNo();
                    const column = stmt.getOriginPositionInfo().getColNo();
                    const problem = 'Interop';
                    const desc = `${this.metaData.description} (${RULE_ID})`;
                    const severity = this.metaData.severity;
                    const ruleId = this.rule.ruleId;
                    const filePath = method.getDeclaringArkFile()?.getFilePath() ?? '';
                    const defeats = new Defects(line, column, column, problem, desc, severity, ruleId, filePath, '', true, false, false);
                    this.issues.push(new IssueReport(defeats, undefined));
                }
            }
        });
    }

    private findCallsite(method: ArkMethod, targets: Map<MethodSignature, boolean[]>, scene: Scene) {
        const stmts = method.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            const invoke = stmt.getInvokeExpr();
            if (!invoke) {
                continue;
            }
            const methodSig = invoke.getMethodSignature();
            if (!targets.has(methodSig)) {
                continue;
            }
            invoke.getArgs().forEach((arg, idx) => {
                if (this.getTypeDefinedLang(arg.getType(), method.getDeclaringArkFile(), scene) !== Language.ARKTS1_2) {
                    return;
                }
                targets.get(methodSig)![idx] = true;
            });
        }
    }

    private getTypeDefinedLang(type: Type, defaultFile: ArkFile, scene: Scene): Language {
        let file;
        if (type instanceof ClassType) {
            file = scene.getFile(type.getClassSignature().getDeclaringFileSignature());
        } else if (type instanceof FunctionType) {
            file = scene.getFile(type.getMethodSignature().getDeclaringClassSignature().getDeclaringFileSignature());
        } else {
            file = defaultFile;
        }
        if (file) {
            return file.getLanguage();
        } else {
            logger.error(`fail to identify which file the type definition ${type.toString()} is in.`);
            return Language.UNKNOWN;
        }
    }
}  