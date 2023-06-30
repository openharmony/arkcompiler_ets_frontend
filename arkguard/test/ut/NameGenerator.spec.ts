/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import {describe, it} from 'mocha';
import {assert} from 'chai';
import {getNameGenerator, NameGeneratorType} from '../../src/generator/NameFactory';
import {NameGeneratorOptions} from '../../src/generator/INameGenerator';

const orderedName = [
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z', 'a1', 'b1', 'c1', 'd1',
  'e1', 'f1', 'g1', 'h1', 'i1', 'j1', 'k1', 'l1', 'm1', 'n1',
  'o1', 'p1', 'q1', 'r1', 's1', 't1', 'u1', 'v1', 'w1', 'x1',
  'y1', 'z1', 'a2', 'b2', 'c2', 'd2', 'e2', 'f2', 'g2', 'h2',
  'i2', 'j2', 'k2', 'l2', 'm2', 'n2', 'o2', 'p2', 'q2', 'r2',
  's2', 't2', 'u2', 'v2', 'w2', 'x2', 'y2', 'z2', 'a3', 'b3',
  'c3', 'd3', 'e3', 'f3', 'g3', 'h3', 'i3', 'j3', 'k3', 'l3',
  'm3', 'n3', 'o3', 'p3', 'q3', 'r3', 's3', 't3', 'u3', 'v3',
  'w3', 'x3', 'y3', 'z3'
];

describe("test for name generator", function () {
  describe('ordered name generator test', function () {
    it('ordered name generator check', function () {
      const orderedGenerator = getNameGenerator(NameGeneratorType.ORDERED);

      for (let i = 0; i < 104; i++) {
        assert.strictEqual(orderedGenerator.getName(), orderedName[i]);
      }
    });
  });

  describe('disordered name generator test', function () {
    const disorderGenerator = getNameGenerator(NameGeneratorType.DISORDERED);
    let arr = []
    for (let i = 0; i < 104; i++) {
      arr.push(disorderGenerator.getName());
    }

    it('disordered name generator check value', function () {
      for (let i = 1; i < 5; i++) {
        const targetName = orderedName.slice(26 * (i - 1), 26 * i);
        const sliceArr = arr.slice(26 * (i - 1), 26 * i);
        sliceArr.sort();
        sliceArr.forEach(((value, index) => {
          assert.strictEqual(value, targetName[index]);
        }));
      }
    });

    it('disordered name generator check order', function () {
      let count = 0;

      for (let i = 2; i < 26; i++) {
        const downConsecutive = (arr[i - 2].charCodeAt(0) - arr[i - 1].charCodeAt(0) === 1) &&
          (arr[i - 1].charCodeAt(0) - arr[i].charCodeAt(0) === 1);
        if (downConsecutive) {
          count++;
        }

        const upConsecutive = (arr[i].charCodeAt(0) - arr[i - 1].charCodeAt(0) === 1) &&
          (arr[i - 1].charCodeAt(0) - arr[i - 2].charCodeAt(0) === 1);
        if (upConsecutive) {
          count = count + 1;
        }
      }

      assert.isNotTrue(count > 5);
    });
  });

  describe('underline name generator test', function () {
    it('underline name generator no option check value', function () {
      const underlineGenerator = getNameGenerator(NameGeneratorType.UNDERLINE);
      for (let i = 0; i < 128; i++) {
        assert.strictEqual(underlineGenerator.getName(), '_'.repeat(i + 1));
      }

      assert.isNull(underlineGenerator.getName());
    });

    it('underline name generator with option check value', function () {
      const options: NameGeneratorOptions = {
        underlineMaxLength: 120
      };

      const underlineGenerator = getNameGenerator(NameGeneratorType.UNDERLINE, options);
      for (let i = 0; i < options.underlineMaxLength; i++) {
        assert.strictEqual(underlineGenerator.getName(), '_'.repeat(i + 1));
      }

      assert.isNull(underlineGenerator.getName());
    });
  });

  describe('hex name generator test', function () {
    it('hex name generator no option check length', function () {
      const hexGenerator = getNameGenerator(NameGeneratorType.HEX);
      for (let i = 0; i < 128; i++) {
        assert.strictEqual(hexGenerator.getName().length, 8);
      }
    });

    it('hex name generator no option check value', function () {
      const hexGenerator = getNameGenerator(NameGeneratorType.HEX);
      for (let i = 0; i < 128; i++) {
        const hexName = hexGenerator.getName();

        assert.isFalse(hexName.startsWith('_0x'));
        assert.isFalse(hexName.endsWith('_'));

        for (let j = 0; j < 8; j++) {
          const isHex = (hexName[j] >= '0' && hexName[j] <= '9') || (hexName[j] >= 'a' && hexName[j] <= 'f');
          assert.isTrue(isHex);
        }
      }
    });

    it('hex name generator with option check length', function () {
      const options = {
        hexLength: 10
      };

      const hexGenerator = getNameGenerator(NameGeneratorType.HEX, options);
      for (let i = 0; i < 128; i++) {
        assert.strictEqual(hexGenerator.getName().length, 20);
      }
    });

    it('hex name generator with option check value', function () {
      const options = {
        hexLength: 10
      };

      const hexGenerator = getNameGenerator(NameGeneratorType.HEX, options);
      for (let i = 0; i < 128; i++) {
        const hexName = hexGenerator.getName();

        assert.isFalse(hexName.startsWith('_0x'));
        assert.isFalse(hexName.endsWith('_'));

        for (let j = 0; j < 20; j++) {
          const isHex = (hexName[j] >= '0' && hexName[j] <= '9') || (hexName[j] >= 'a' && hexName[j] <= 'f');
          assert.isTrue(isHex);
        }
      }
    });
  });

  describe('dictionary name generator test', function () {
    const noOptionTarget = [
      'hello', 'Hello', 'hEllo', 'HEllo', 'heLlo',
      'HeLlo', 'hELlo', 'HELlo', 'helLo', 'HelLo',
      'hElLo', 'HElLo', 'heLLo', 'HeLLo', 'hELLo',
      'HELLo', 'hellO', 'HellO', 'hEllO', 'HEllO',
      'heLlO', 'HeLlO', 'hELlO', 'HELlO', 'helLO',
      'HelLO', 'hElLO', 'HElLO', 'heLLO', 'HeLLO',
      'hELLO', 'HELLO', 'world', 'World', 'wOrld',
      'WOrld', 'woRld', 'WoRld', 'wORld', 'WORld',
      'worLd', 'WorLd', 'wOrLd', 'WOrLd', 'woRLd',
      'WoRLd', 'wORLd', 'WORLd', 'worlD', 'WorlD',
      'wOrlD', 'WOrlD', 'woRlD', 'WoRlD', 'wORlD',
      'WORlD', 'worLD', 'WorLD', 'wOrLD', 'WOrLD',
      'woRLD', 'WoRLD', 'wORLD', 'WORLD', 'dictionary',
      'Dictionary', 'dIctionary', 'DIctionary', 'diCtionary', 'DiCtionary',
      'dICtionary', 'DICtionary', 'dicTionary', 'DicTionary', 'dIcTionary',
      'DIcTionary', 'diCTionary', 'DiCTionary', 'dICTionary', 'DICTionary',
      'dictIonary', 'DictIonary', 'dIctIonary', 'DIctIonary', 'diCtIonary',
      'DiCtIonary', 'dICtIonary', 'DICtIonary', 'dicTIonary', 'DicTIonary',
      'dIcTIonary', 'DIcTIonary', 'diCTIonary', 'DiCTIonary', 'dICTIonary',
      'DICTIonary', 'dictiOnary', 'DictiOnary', 'dIctiOnary', 'DIctiOnary'
    ];

    const optionTarget = [
      'tom', 'Tom', 'tOm', 'TOm', 'toM', 'ToM', 'tOM', 'TOM', 'jerry', 'Jerry',
      'jErry', 'JErry', 'jeRry', 'JeRry', 'jERry', 'JERry', 'jerRy', 'JerRy',
      'jErRy', 'JErRy', 'jeRRy', 'JeRRy', 'jERRy', 'JERRy', 'jerrY', 'JerrY',
      'jErrY', 'JErrY', 'jeRrY', 'JeRrY', 'jERrY', 'JERrY', 'jerRY', 'JerRY',
      'jErRY', 'JErRY', 'jeRRY', 'JeRRY', 'jERRY', 'JERRY', 'hellokitty', 'Hellokitty',
      'hEllokitty', 'HEllokitty', 'heLlokitty', 'HeLlokitty', 'hELlokitty', 'HELlokitty',
      'helLokitty', 'HelLokitty', 'hElLokitty', 'HElLokitty', 'heLLokitty', 'HeLLokitty',
      'hELLokitty', 'HELLokitty', 'hellOkitty', 'HellOkitty', 'hEllOkitty', 'HEllOkitty',
      'heLlOkitty', 'HeLlOkitty', 'hELlOkitty', 'HELlOkitty', 'helLOkitty', 'HelLOkitty',
      'hElLOkitty', 'HElLOkitty', 'heLLOkitty', 'HeLLOkitty', 'hELLOkitty', 'HELLOkitty',
      'helloKitty', 'HelloKitty', 'hElloKitty', 'HElloKitty', 'heLloKitty', 'HeLloKitty',
      'hELloKitty', 'HELloKitty', 'helLoKitty', 'HelLoKitty', 'hElLoKitty', 'HElLoKitty',
      'heLLoKitty', 'HeLLoKitty', 'hELLoKitty', 'HELLoKitty', 'hellOKitty', 'HellOKitty',
      'hEllOKitty', 'HEllOKitty', 'heLlOKitty', 'HeLlOKitty', 'hELlOKitty', 'HELlOKitty',
      'helLOKitty', 'HelLOKitty', 'hElLOKitty', 'HElLOKitty'];

    it('dictionary name generator no option check value', function () {
      const dictGenerator = getNameGenerator(NameGeneratorType.DICTIONARY);
      let arr = [];
      for (let i = 0; i < 100; i++) {
        const nameGet = dictGenerator.getName();
        assert.isNotNull(nameGet);
        arr.push(nameGet);
      }

      arr.forEach(((value, index) => {
        assert.strictEqual(value, noOptionTarget[index]);
      }));
    });

    it('dictionary name generator with option check value', function () {
      const options = {
        dictionaryList: ['tom', 'jerry', 'helloKitty', 'jojo', 'betty']
      };

      const dictGenerator = getNameGenerator(NameGeneratorType.DICTIONARY, options);
      let arr = [];
      for (let i = 0; i < 100; i++) {
        const nameGet = dictGenerator.getName();
        assert.isNotNull(nameGet);
        arr.push(nameGet);
      }

      arr.forEach(((value, index) => {
        assert.strictEqual(value, optionTarget[index]);
      }));
    });
  });

  describe('reserved name generator test', function () {
    const targetNames = [
      'ιet', 'lèt', 'ιèt', 'rèturn', 'retυrn', 'rètυrn', 'returη', 'rèturη',
      'retυrη', 'rètυrη', 'þreak', 'brèak', 'þrèak', 'breαk', 'þreαk', 'brèαk',
      'þrèαk', 'breaκ', 'þreaκ', 'brèaκ', 'þrèaκ', 'breακ', 'þreακ', 'brèακ',
      'þrèακ', 'çontinue', 'cοntinue', 'çοntinue', 'coηtinue', 'çoηtinue',
      'cοηtinue', 'çοηtinue', 'contìnue', 'çontìnue', 'cοntìnue', 'çοntìnue',
      'coηtìnue', 'çoηtìnue', 'cοηtìnue', 'çοηtìnue', 'contiηue', 'çontiηue',
      'cοntiηue', 'çοntiηue', 'coηtiηue', 'çoηtiηue', 'cοηtiηue', 'çοηtiηue',
      'contìηue', 'çontìηue', 'cοntìηue', 'çοntìηue', 'coηtìηue', 'çoηtìηue',
      'cοηtìηue', 'çοηtìηue', 'continυe', 'çontinυe', 'cοntinυe', 'çοntinυe',
      'coηtinυe', 'çoηtinυe', 'cοηtinυe', 'çοηtinυe', 'contìnυe', 'çontìnυe',
      'cοntìnυe', 'çοntìnυe', 'coηtìnυe', 'çoηtìnυe', 'cοηtìnυe', 'çοηtìnυe',
      'contiηυe', 'çontiηυe', 'cοntiηυe', 'çοntiηυe', 'coηtiηυe', 'çoηtiηυe',
      'cοηtiηυe', 'çοηtiηυe', 'contìηυe', 'çontìηυe', 'cοntìηυe', 'çοntìηυe',
      'coηtìηυe', 'çoηtìηυe', 'cοηtìηυe', 'çοηtìηυe', 'continuè', 'çontinuè',
      'cοntinuè', 'çοntinuè', 'coηtinuè', 'çoηtinuè', 'cοηtinuè', 'çοηtinuè',
      'contìnuè', 'çontìnuè', 'cοntìnuè', 'çοntìnuè'
    ];

    it('reserved name generator check value', function () {

      const reservedGenerator = getNameGenerator(NameGeneratorType.RESERVED_NAME);
      let arr = [];
      for (let i = 0; i < 100; i++) {
        const nameGet = reservedGenerator.getName();
        assert.isNotNull(nameGet);
        arr.push(nameGet);
      }

      arr.forEach(((value, index) => {
        assert.strictEqual(value, targetNames[index]);
      }));
    });
  });
});
