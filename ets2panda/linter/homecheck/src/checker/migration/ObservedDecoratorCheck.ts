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

import { ArkAssignStmt, ArkClass, ArkField, ArkNewExpr, ClassType, Local, Scene } from "arkanalyzer";
import { ClassCategory } from 'arkanalyzer/lib/core/model/ArkClass';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, ClassMatcher, MatcherTypes, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'ObservedDecoratorCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: "",
    description: ''
};

export class ObservedDecoratorCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private clsMatcher: ClassMatcher = {
        matcherType: MatcherTypes.CLASS,
    };

    public registerMatchers(): MatcherCallback[] {
        const matchClsCb: MatcherCallback = {
            matcher: this.clsMatcher,
            callback: this.check
        };
        return [matchClsCb];
    }

    public check = (arkClass: ArkClass): void => {
        const scene = arkClass.getDeclaringArkFile().getScene();
        for (const field of arkClass.getFields()) {
            if (!field.getDecorators().some(d => d.getKind() === 'State')) {
                continue;
            }
            const fieldType = field.getType();
            if (!(fieldType instanceof ClassType)) {
                continue;
            }
            const fieldClass = scene.getClass(fieldType.getClassSignature());
            const initializers = field.getInitializer();
            let canfindAllTargets = true;
            let targets: Set<ArkClass> = new Set();
            if (fieldClass?.getCategory() === ClassCategory.CLASS) {
                targets.add(fieldClass);
            }
            let locals: Set<Local> = new Set();
            let start = (initializers[initializers.length - 1] as ArkAssignStmt).getRightOp() as Local;
            locals.add(start);
            for (const stmt of initializers.slice(0, -1).reverse()) {
                if (!(stmt instanceof ArkAssignStmt)) {
                    continue;
                }

                const leftOp = stmt.getLeftOp();
                const rightOp = stmt.getRightOp();
                if (!(leftOp instanceof Local)) {
                    continue;
                }
                if (!locals.has(leftOp)) {
                    continue;
                }
                if (rightOp instanceof Local) {
                    locals.add(rightOp);
                } else if (rightOp instanceof ArkNewExpr) {
                    canfindAllTargets = this.handleNewExpr(scene, rightOp, targets);
                } else {
                    canfindAllTargets = false;
                }
            }

            for (const target of targets) {
                const pos = this.getClassPos(target);
                this.addIssueReport(pos);
            }

            if (!canfindAllTargets) {
                const pos = this.getFieldPos(field);
                this.addIssueReport(pos);
            }
        }
    };

    private handleNewExpr(scene: Scene, rightOp: ArkNewExpr, targets: Set<ArkClass>): boolean {
        let canfindAllTargets = true;

        const target = scene.getClass(rightOp.getClassType().getClassSignature());
        if (target && !target.isAnonymousClass()) {
            targets.add(target);
            const superClasses = target.getAllHeritageClasses();
            for (const superCls of superClasses) {
                if (superCls.getCategory() === ClassCategory.CLASS) {
                    targets.add(superCls);
                }
            }
        } else {
            canfindAllTargets = false;
        }
        return canfindAllTargets;
    }

    private getClassPos(cls: ArkClass): { line: number; startCol: number; endCol: number; filePath: string; } {
        const arkFile = cls.getDeclaringArkFile();
        if (arkFile) {
            const originPath = arkFile.getFilePath();
            const line = cls.getLine();
            const startCol = cls.getColumn();
            const endCol = startCol;
            return { line, startCol, endCol, filePath: originPath };
        } else {
            logger.debug('ArkFile is null.');
            return { line: -1, startCol: -1, endCol: -1, filePath: '' };
        }
    }

    private getFieldPos(field: ArkField): { line: number; startCol: number; endCol: number; filePath: string; } {
        const arkFile = field.getDeclaringArkClass().getDeclaringArkFile();
        const pos = field.getOriginPosition();
        if (arkFile && pos) {
            const originPath = arkFile.getFilePath();
            const line = pos.getLineNo();
            const startCol = pos.getColNo();
            const endCol = startCol;
            return { line, startCol, endCol, filePath: originPath };
        } else {
            logger.debug('ArkFile is null.');
            return { line: -1, startCol: -1, endCol: -1, filePath: '' };
        }
    }

    private addIssueReport(warnInfo: { line: number; startCol: number; endCol: number; filePath: string; }) {
        const severity = this.rule.alert ?? this.metaData.severity;
        let defects = new Defects(warnInfo.line, warnInfo.startCol, warnInfo.endCol, this.metaData.description, severity, this.rule.ruleId,
            warnInfo.filePath, this.metaData.ruleDocPath, true, false, false);
        this.issues.push(new IssueReport(defects, undefined));
    }
}