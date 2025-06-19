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

import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule } from '../../model/Rule';
import { Defects, IssueReport } from '../../model/Defects';
import { FileMatcher, MatcherCallback, MatcherTypes } from '../../matcher/Matchers';
import {
    AbstractInvokeExpr,
    ArkAssignStmt,
    ArkClass,
    ArkFile,
    ArkMethod,
    ArkNamespace,
    ArkNewExpr,
    ClassType,
    FunctionType,
    ImportInfo,
    Local,
    LOG_MODULE_TYPE,
    Logger,
    Scene,
    Stmt,
    Type,
} from 'arkanalyzer';
import { ExportType } from 'arkanalyzer/lib/core/model/ArkExport';
import { WarnInfo } from '../../utils/common/Utils';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';
import { getLanguageStr } from './Utils';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropBoxedTypeCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

const ruleId: string = '@migration/interop-boxed-type-check';
const s2dRuleId: string = 'arkts-interop-s2d-boxed-type';
const d2sRuleId: string = 'arkts-interop-d2s-boxed-type';
const ts2sRuleId: string = 'arkts-interop-ts2s-boxed-type';
const js2RuleId: string = 'arkts-interop-js2s-boxed-type';

const BOXED_SET: Set<string> = new Set<string>(['String', 'Boolean', 'Number']);

type CheckedObj = {
    namespaces: Map<string, boolean | null>;
    classes: Map<string, boolean | null>;
    methods: Map<string, boolean | null>;
};

export class InteropBoxedTypeCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private fileMatcher: FileMatcher = {
        matcherType: MatcherTypes.FILE,
    };

    public registerMatchers(): MatcherCallback[] {
        const fileMatcher: MatcherCallback = {
            matcher: this.fileMatcher,
            callback: this.check,
        };
        return [fileMatcher];
    }

    public check = (arkFile: ArkFile): void => {
        let hasChecked: CheckedObj = {
            namespaces: new Map<string, boolean | null>(),
            classes: new Map<string, boolean | null>(),
            methods: new Map<string, boolean | null>(),
        };
        const scene = arkFile.getScene();
        // Import对象对应的Export信息的推导在类型推导过程中是懒加载机制，调用getLazyExportInfo接口会自动进行推导
        arkFile.getImportInfos().forEach(importInfo => {
            const exportInfo = importInfo.getLazyExportInfo();
            // TODO: import * from xxx是如何表示的？
            if (exportInfo === null) {
                // 导入内置库时为null
                return;
            }
            const arkExport = exportInfo.getArkExport();
            if (arkExport === null || arkExport === undefined) {
                // 按正常流程，上面的exportInfo不为null时，这里一定会将实际找到的export对象set为arkExport，所以这里应该走不到
                // import三方包时为null，未推导为undefined，推导后无结果为null
                return;
            }

            const exportType = arkExport.getExportType();
            // 如果import的是sdk，exportType可能是namespace等，但是找不到body体等详细赋值语句等内容，所以不影响如下的判断
            switch (exportType) {
                case ExportType.NAME_SPACE:
                    this.findBoxedTypeInNamespace(importInfo, arkExport as ArkNamespace, scene, hasChecked);
                    return;
                case ExportType.CLASS:
                    this.findBoxedTypeInClass(importInfo, arkExport as ArkClass, scene, hasChecked);
                    return;
                case ExportType.METHOD:
                    this.findBoxedTypeWithMethodReturn(importInfo, arkExport as ArkMethod, scene, hasChecked);
                    return;
                case ExportType.LOCAL:
                    this.findBoxedTypeWithLocal(importInfo, arkExport as Local, scene, hasChecked);
                    return;
                default:
                    return;
            }
        });
    };

    private findBoxedTypeInNamespace(
        importInfo: ImportInfo,
        arkNamespace: ArkNamespace,
        scene: Scene,
        hasChecked: CheckedObj
    ): boolean | null {
        // 判断namespace是否已查找过，避免陷入死循环
        const existing = hasChecked.namespaces.get(arkNamespace.getSignature().toString());
        if (existing !== undefined) {
            return existing;
        }
        hasChecked.namespaces.set(arkNamespace.getSignature().toString(), null);
        const exports = arkNamespace.getExportInfos();
        let found: boolean | null = null;
        for (const exportInfo of exports) {
            const arkExport = exportInfo.getArkExport();
            if (arkExport === undefined) {
                continue;
            }

            if (arkExport === null) {
                // ArkAnalyzer此处有一个问题，无法区分export local是来自arkfile还是arknamespace，导致类型推导推出来是null
                continue;
            }
            if (arkExport instanceof Local) {
                found = this.findBoxedTypeWithLocal(importInfo, arkExport, scene, hasChecked);
            } else if (arkExport instanceof ArkMethod) {
                found = this.findBoxedTypeWithMethodReturn(importInfo, arkExport, scene, hasChecked);
            } else if (arkExport instanceof ArkClass) {
                found = this.findBoxedTypeInClass(importInfo, arkExport, scene, hasChecked);
            } else if (arkExport instanceof ArkNamespace) {
                found = this.findBoxedTypeInNamespace(importInfo, arkExport, scene, hasChecked);
            }
            if (found) {
                hasChecked.namespaces.set(arkNamespace.getSignature().toString(), true);
                return true;
            }
        }
        hasChecked.namespaces.set(arkNamespace.getSignature().toString(), false);
        return false;
    }

    private isClassHasBoxedType(arkClass: ArkClass, scene: Scene, hasChecked: CheckedObj): boolean | null {
        // step0: 判断class是否已查找过，避免陷入死循环
        const existing = hasChecked.classes.get(arkClass.getSignature().toString());
        if (existing !== undefined) {
            return existing;
        }
        hasChecked.classes.set(arkClass.getSignature().toString(), null);
        // step1: 查找class中的所有field，包含static和非static，判断initialized stmts中是否会用boxed类型对象给field赋值
        const allFields = arkClass.getFields();
        for (const field of allFields) {
            // 此处不检查field signature中的Type，因为type直接写String时也表示成Class Type，无法区分是否为new String()生成的
            const initializer = field.getInitializer();
            if (initializer.length < 1) {
                continue;
            }
            const lastStmt = initializer[initializer.length - 1];
            if (!(lastStmt instanceof ArkAssignStmt)) {
                continue;
            }
            if (this.isValueAssignedByBoxed(lastStmt, initializer.slice(0, -1).reverse(), scene, hasChecked)) {
                // 这里没有顺着field的定义语句中使用到的import对象去寻找原始的Boxed类型定义所在的文件的Language，而是直接使用field所在的语言
                // 应该也是ok的，因为上述import chain如何不合法，也会有告警在其import的地方给出
                hasChecked.classes.set(arkClass.getSignature().toString(), true);
                return true;
            }
        }

        // step2: 查找class中的所有非generated method，判断所有的return操作符类型是否为boxed
        const methods = arkClass.getMethods();
        for (const method of methods) {
            const found = this.isMethodReturnHasBoxedType(method, scene, hasChecked);
            if (found) {
                hasChecked.classes.set(arkClass.getSignature().toString(), true);
                return true;
            }
        }
        hasChecked.classes.set(arkClass.getSignature().toString(), false);
        return false;
    }

    private isMethodReturnHasBoxedType(arkMethod: ArkMethod, scene: Scene, hasChecked: CheckedObj): boolean | null {
        // 判断method是否已查找过，避免陷入死循环
        const existing = hasChecked.methods.get(arkMethod.getSignature().toString());
        if (existing !== undefined) {
            return existing;
        }
        hasChecked.methods.set(arkMethod.getSignature().toString(), null);
        const returnOps = arkMethod.getReturnValues();
        for (const op of returnOps) {
            if (this.isBoxedType(op.getType())) {
                hasChecked.methods.set(arkMethod.getSignature().toString(), true);
                return true;
            }
            if (op instanceof Local && this.isLocalHasBoxedType(op, scene, hasChecked)) {
                hasChecked.methods.set(arkMethod.getSignature().toString(), true);
                return true;
            }
        }
        hasChecked.methods.set(arkMethod.getSignature().toString(), false);
        return false;
    }

    // 此处不检查local的Type，因为type直接写String时也表示成Class Type，无法区分是否为new String()生成的
    private isLocalHasBoxedType(local: Local, scene: Scene, hasChecked: CheckedObj): boolean {
        const method = local.getDeclaringStmt()?.getCfg().getDeclaringMethod();
        if (method === undefined) {
            return false;
        }
        const stmts = method.getCfg()?.getStmts().reverse();
        if (stmts === undefined || stmts.length < 1) {
            return false;
        }

        const declaringStmt = local.getDeclaringStmt();
        if (
            declaringStmt !== null &&
            declaringStmt instanceof ArkAssignStmt &&
            this.isValueAssignedByBoxed(declaringStmt, stmts, scene, hasChecked)
        ) {
            return true;
        }
        for (const stmt of local.getUsedStmts()) {
            if (stmt instanceof ArkAssignStmt) {
                const leftOp = stmt.getLeftOp();
                if (
                    leftOp instanceof Local &&
                    leftOp.toString() === local.toString() &&
                    this.isValueAssignedByBoxed(stmt, stmts, scene, hasChecked)
                ) {
                    return true;
                }
            }
        }
        return false;
    }

    private findBoxedTypeInClass(
        importInfo: ImportInfo,
        arkClass: ArkClass,
        scene: Scene,
        hasChecked: CheckedObj
    ): boolean {
        const importOpPosition = importInfo.getOriginTsPosition();
        const warnInfo: WarnInfo = {
            line: importOpPosition.getLineNo(),
            startCol: importOpPosition.getColNo(),
            endCol: importOpPosition.getColNo(),
            filePath: importInfo.getDeclaringArkFile().getFilePath(),
        };
        const currLanguage = importInfo.getLanguage();
        const result = this.isClassHasBoxedType(arkClass, scene, hasChecked);
        if (result) {
            this.addIssueReport(warnInfo, currLanguage, arkClass.getLanguage());
            return true;
        }
        return false;
    }

    private findBoxedTypeWithMethodReturn(
        importInfo: ImportInfo,
        arkMethod: ArkMethod,
        scene: Scene,
        hasChecked: CheckedObj
    ): boolean {
        const importOpPostion = importInfo.getOriginTsPosition();
        const warnInfo: WarnInfo = {
            line: importOpPostion.getLineNo(),
            startCol: importOpPostion.getColNo(),
            endCol: importOpPostion.getColNo(),
            filePath: importInfo.getDeclaringArkFile().getFilePath(),
        };
        const currLanguage = importInfo.getLanguage();

        // 此处不检查method signature中的return Type，因为return type直接写String时也表示成Class Type，无法区分是否为new String()生成的
        if (this.isMethodReturnHasBoxedType(arkMethod, scene, hasChecked)) {
            this.addIssueReport(warnInfo, currLanguage, arkMethod.getLanguage());
            return true;
        }
        return false;
    }

    private findBoxedTypeWithLocal(
        importInfo: ImportInfo,
        local: Local,
        scene: Scene,
        hasChecked: CheckedObj
    ): boolean {
        const importOpPosition = importInfo.getOriginTsPosition();
        const warnInfo: WarnInfo = {
            line: importOpPosition.getLineNo(),
            startCol: importOpPosition.getColNo(),
            endCol: importOpPosition.getColNo(),
            filePath: importInfo.getDeclaringArkFile().getFilePath(),
        };
        const currLanguage = importInfo.getLanguage();
        const method = local.getDeclaringStmt()?.getCfg().getDeclaringMethod();
        if (method === undefined) {
            return false;
        }
        if (this.isLocalHasBoxedType(local, scene, hasChecked)) {
            this.addIssueReport(warnInfo, currLanguage, method.getLanguage());
            return true;
        }
        return false;
    }

    private isBoxedType(checkType: Type): boolean {
        // ArkAnalyzer表示new String()形式的类型为ClassType，Class Name为String、Boolean、Number
        // TODO: 此处底座有一个bug，表示String()时推导为Unknown Type，正确的应该为string，但是不影响本规则的判断
        return checkType instanceof ClassType && BOXED_SET.has(checkType.getClassSignature().getClassName());
    }

    private addIssueReport(warnInfo: WarnInfo, currLanguage: Language, targetLanguage: Language): void {
        const interopRule = this.getInteropRule(currLanguage, targetLanguage);
        if (interopRule === null) {
            return;
        }
        const severity = this.metaData.severity;
        const currLanStr = getLanguageStr(currLanguage);
        const targetLanStr = getLanguageStr(targetLanguage);
        const problem = 'Interop';
        const describe = `Could not import object with boxed type from ${targetLanStr} to ${currLanStr} (${interopRule})`;
        let defects = new Defects(
            warnInfo.line,
            warnInfo.startCol,
            warnInfo.endCol,
            problem,
            describe,
            severity,
            ruleId,
            warnInfo.filePath,
            this.metaData.ruleDocPath,
            true,
            false,
            false
        );
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getInteropRule(currLanguage: Language, targetLanguage: Language): string | null {
        if (currLanguage === Language.ARKTS1_1) {
            if (targetLanguage === Language.ARKTS1_2) {
                return s2dRuleId;
            }
        } else if (currLanguage === Language.ARKTS1_2) {
            if (targetLanguage === Language.TYPESCRIPT) {
                return ts2sRuleId;
            }
            if (targetLanguage === Language.ARKTS1_1) {
                return d2sRuleId;
            }
            if (targetLanguage === Language.JAVASCRIPT) {
                return js2RuleId;
            }
        }
        return null;
    }

    // lastStmt为当前需要查找的对象的赋值语句，左值为查找对象，右值为往前继续查找的赋值起点
    // reverseStmtChain为以待查找对象为起点，所有一系列赋值语句的倒序排列
    private isValueAssignedByBoxed(
        lastStmt: ArkAssignStmt,
        previousReverseChain: Stmt[],
        scene: Scene,
        hasChecked: CheckedObj
    ): boolean {
        let locals: Set<Local> = new Set();
        const targetLocal = lastStmt.getRightOp();
        const targetLocalType = targetLocal.getType();
        if (this.isBoxedType(targetLocalType)) {
            return true;
        }
        if (targetLocalType instanceof ClassType) {
            const arkClass = scene.getClass(targetLocalType.getClassSignature());
            if (arkClass !== null && this.isClassHasBoxedType(arkClass, scene, hasChecked)) {
                return true;
            }
        }
        if (targetLocalType instanceof FunctionType) {
            const arkMethod = scene.getMethod(targetLocalType.getMethodSignature());
            if (arkMethod !== null && this.isMethodReturnHasBoxedType(arkMethod, scene, hasChecked)) {
                return true;
            }
        }

        if (!(targetLocal instanceof Local)) {
            return false;
        }
        locals.add(targetLocal);

        const rightOp = lastStmt.getRightOp();
        if (!(rightOp instanceof Local)) {
            return false;
        }
        locals.add(rightOp);
        for (const stmt of previousReverseChain) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const leftOp = stmt.getLeftOp();
            const rightOp = stmt.getRightOp();
            if (!(leftOp instanceof Local) || !locals.has(leftOp)) {
                continue;
            }
            if (rightOp instanceof Local) {
                locals.add(rightOp);
                continue;
            }
            if (rightOp instanceof ArkNewExpr) {
                if (this.isBoxedType(rightOp.getClassType())) {
                    return true;
                }
                continue;
            }
            if (rightOp instanceof AbstractInvokeExpr) {
                if (this.isBoxedType(rightOp.getType())) {
                    return true;
                }
                continue;
            }
        }
        return false;
    }
}
