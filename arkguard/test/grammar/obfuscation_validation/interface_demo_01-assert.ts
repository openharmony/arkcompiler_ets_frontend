import fs from 'fs';
import path from 'path';
import assert from 'assert';

const filePath = path.join(__filename, '../interface_demo_01_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8');

const expectation = `export interface Interface01 {
    interfaceP1: number;
    "interfaceP2": number;
    ["interfaceP1"]: number;
}
export const Object01 = {
    objectP1: 10,
    "objectP2": 11,
    ['objectP3']: 12,
};
export class class01 {
    classP1;
    11 = 4;
    'classP2' = 3;
    ['classP3'] = 2;
    constructor(public classP5 = 1, private classP6 = 2, protected classP7 = 3, readonly classP8 = { classP9: 4 }) {
        this.classP1 = {
            classP10: 3
        };
    }
    classP11 = class class02 {
        classP12 = 3;
    };
    get classP13() { return 1; }
    set classP14(a) { }
}
export enum enum01 {
    enumP1,
    'enumP2',
    ['enumP3']
}
export type typeAlia01 = {
    typeP1;
    'typeP2';
    ['typeP3'];
};`

assert.strictEqual(actual.trim(), expectation.trim());