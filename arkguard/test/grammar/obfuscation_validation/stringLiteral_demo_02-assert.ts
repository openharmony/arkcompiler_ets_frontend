import fs from 'fs';
import path from 'path';
import assert from 'assert';

const filePath = path.join(__filename, '../stringLiteral_demo_02_use.ts');
const actual = fs.readFileSync(filePath, 'utf-8');

const expectation = `interface Interface11 {
    "interfaceP12": number;
    ["interfaceP13"]: number;
}
const Object11 = {
    "objectP12": 11,
    ['objectP13']: 12,
};
class class11 {
    'classP12' = 3;
    ['classP13'] = 2;
}
enum enum11 {
    'enumP12',
    ['enumP13']
}
Object11['paramerter01'];`

assert.strictEqual(actual.trim(), expectation.trim());