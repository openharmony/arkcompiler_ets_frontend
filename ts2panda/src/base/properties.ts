/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

import * as ts from "typescript";
import { isValidIndex } from "../expression/memberAccessExpression";
import * as jshelpers from "../jshelpers";

export enum PropertyKind {
    VARIABLE,
    CONSTANT,
    COMPUTED, // Property with computed value (execution time).
    PROTOTYPE,
    ACCESSOR,
    SPREAD
}

export class Property {
    private propKind: PropertyKind;
    private valueNode: ts.Node | undefined;
    private setterNode: ts.SetAccessorDeclaration | undefined;
    private getterNode: ts.GetAccessorDeclaration | undefined;
    private compiled: boolean = false;
    private redeclared: boolean = false;
    private name: string | number | ts.ComputedPropertyName | undefined;

    constructor(propKind: PropertyKind, name: string | number | ts.ComputedPropertyName | undefined) {
        this.propKind = propKind;
        if (typeof (name) != 'undefined') {
            this.name = name;
        }
    }

    setCompiled(): void {
        this.compiled = true;
    }

    setRedeclared(): void {
        this.redeclared = true;
    }

    isCompiled(): boolean {
        return this.compiled;
    }

    isRedeclared(): boolean {
        return this.redeclared;
    }

    getName(): string | number | ts.ComputedPropertyName {
        if (typeof (this.name) === 'undefined') {
            throw new Error("this property doesn't have a name");
        }
        return this.name;
    }

    getKind(): PropertyKind {
        return this.propKind;
    }

    getValue(): ts.Node {
        if (this.propKind === PropertyKind.ACCESSOR) {
            throw new Error("Accessor doesn't have valueNode");
        }
        return this.valueNode!;
    }

    getGetter(): ts.GetAccessorDeclaration {
        return this.getterNode;
    }

    getSetter(): ts.SetAccessorDeclaration {
        return this.setterNode;
    }

    setValue(valueNode: ts.Node): void {
        this.valueNode = valueNode;
        this.getterNode = undefined;
        this.setterNode = undefined;
    }

    setGetter(getter: ts.GetAccessorDeclaration): void {
        if (this.propKind != PropertyKind.ACCESSOR) {
            this.valueNode = undefined;
            this.setterNode = undefined;
            this.propKind = PropertyKind.ACCESSOR;
        }
        this.getterNode = getter;
    }

    setSetter(setter: ts.SetAccessorDeclaration): void {
        if (this.propKind != PropertyKind.ACCESSOR) {
            this.valueNode = undefined;
            this.getterNode = undefined;
            this.propKind = PropertyKind.ACCESSOR;
        }
        this.setterNode = setter;
    }

    setKind(propKind: PropertyKind): void {
        this.propKind = propKind;
    }
}


export function generatePropertyFromExpr(expr: ts.ObjectLiteralExpression): Property[] {
    let hasProto: boolean = false;
    let properties: Property[] = [];
    let namedPropertyMap: Map<string, number> = new Map<string, number>();

    expr.properties.forEach(property => {
        switch (property.kind) {
            case ts.SyntaxKind.PropertyAssignment: {
                if (property.name.kind === ts.SyntaxKind.ComputedPropertyName) {
                    defineProperty(property.name, property, PropertyKind.COMPUTED, properties, namedPropertyMap);
                    break;
                }

                let propName: number | string = <number | string>getPropName(property.name);
                if (propName === "__proto__") {
                    if (!hasProto) {
                        defineProperty(propName, property.initializer, PropertyKind.PROTOTYPE, properties, namedPropertyMap);
                        hasProto = true;
                        break;
                    } else {
                        throw new Error("__proto__ was set multiple times in the object definition.");
                    }
                }

                if (isConstantExpr(property.initializer)) {
                    defineProperty(propName, property.initializer, PropertyKind.CONSTANT, properties, namedPropertyMap);
                } else {
                    defineProperty(propName, property.initializer, PropertyKind.VARIABLE, properties, namedPropertyMap);
                }
                break;
            }
            case ts.SyntaxKind.ShorthandPropertyAssignment: {
                // ShorthandProperty's name always be Identifier
                let propName = jshelpers.getTextOfIdentifierOrLiteral(property.name);
                defineProperty(propName, property.name, PropertyKind.VARIABLE, properties, namedPropertyMap);
                break;
            }
            case ts.SyntaxKind.SpreadAssignment: {
                defineProperty(undefined, property.expression, PropertyKind.SPREAD, properties, namedPropertyMap);
                break;
            }
            case ts.SyntaxKind.MethodDeclaration: {
                let propName = getPropName(property.name);
                if (typeof (propName) === 'string' || typeof (propName) === 'number') {
                    defineProperty(propName, property, PropertyKind.VARIABLE, properties, namedPropertyMap);
                } else {
                    defineProperty(propName, property, PropertyKind.COMPUTED, properties, namedPropertyMap);
                }
                break;
            }
            case ts.SyntaxKind.GetAccessor:
            case ts.SyntaxKind.SetAccessor: {
                let propName = getPropName(property.name);
                if (typeof (propName) === 'string' || typeof (propName) === 'number') {
                    defineProperty(propName, property, PropertyKind.ACCESSOR, properties, namedPropertyMap);
                } else {
                    defineProperty(propName, property, PropertyKind.COMPUTED, properties, namedPropertyMap);
                }
                break;
            }
            default:
                throw new Error("Unreachable Kind");
        }
    });

    return properties;
}

function defineProperty(
    propName: string | number | ts.ComputedPropertyName | undefined,
    propValue: ts.Node,
    propKind: PropertyKind,
    properties: Property[],
    namedPropertyMap: Map<string, number>): void {
    if (propKind === PropertyKind.COMPUTED || propKind === PropertyKind.SPREAD) {
        let prop = new Property(propKind, <ts.ComputedPropertyName | undefined>propName);
        prop.setValue(propValue);
        properties.push(prop);
    } else {
        let prop = new Property(propKind, propName);
        let name_str = propertyKeyAsString(<string | number>propName);

        if (namedPropertyMap.has(name_str)) {
            let prevProp = properties[namedPropertyMap.get(name_str)!];

            if ((prevProp.getKind() === PropertyKind.ACCESSOR || prevProp.getKind() === PropertyKind.CONSTANT) &&
                (propKind === PropertyKind.ACCESSOR || propKind === PropertyKind.CONSTANT)) {
                if (propKind === PropertyKind.ACCESSOR) {
                    if (ts.isGetAccessorDeclaration(propValue)) {
                        prevProp!.setGetter(propValue);
                    } else if (ts.isSetAccessorDeclaration(propValue)) {
                        prevProp!.setSetter(propValue);
                    }
                } else {
                    prevProp!.setValue(propValue);
                    prevProp!.setKind(PropertyKind.CONSTANT);
                }
                return;
            }

            prop.setRedeclared();
        }

        namedPropertyMap.set(name_str, properties.length);
        if (propKind === PropertyKind.ACCESSOR) {
            if (ts.isGetAccessorDeclaration(propValue)) {
                prop.setGetter(propValue);
            } else if (ts.isSetAccessorDeclaration(propValue)) {
                prop.setSetter(propValue);
            }
        } else {
            prop.setValue(propValue);
        }
        properties.push(prop);
    }
}

export function isConstantExpr(node: ts.Node): boolean {
    switch (node.kind) {
        case ts.SyntaxKind.StringLiteral:
        case ts.SyntaxKind.NumericLiteral:
        case ts.SyntaxKind.NullKeyword:
        case ts.SyntaxKind.TrueKeyword:
        case ts.SyntaxKind.FalseKeyword:
            return true;
        default:
            return false;
    }
}

export function propertyKeyAsString(propName: string | number): string {
    if (typeof (propName) === 'number') {
        return propName.toString();
    }
    return propName;
}

export function getPropName(propertyName: ts.PropertyName): string | number | ts.ComputedPropertyName {
    if (ts.isComputedPropertyName(propertyName)) {
        return propertyName;
    }

    let propName: number | string = jshelpers.getTextOfIdentifierOrLiteral(propertyName);

    if (propertyName.kind === ts.SyntaxKind.NumericLiteral) {
        propName = Number.parseFloat(propName);
        if (!isValidIndex(propName)) {
            propName = propName.toString();
        }
    } else if (propertyName.kind === ts.SyntaxKind.StringLiteral) {
        let temp = Number(propName);
        if (!isNaN(Number.parseFloat(propName)) && !isNaN(temp) && isValidIndex(temp) && String(temp) === propName) {
            propName = temp;
        }
    }

    return propName;
}