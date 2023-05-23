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

import {factory, isNumericLiteral, isPropertyAssignment, SyntaxKind} from 'typescript';
import type {BinaryExpression, Node} from 'typescript';
import {randomInt} from 'crypto';

export class NumberObfuscationHelper {
  /**
   * ignore number like property in object
   * let xxx = {
   *     0: 13-1,
   *     1: 1212,
   * }
   *
   * @param node
   */
  public static isTargetNumberNode(node: Node): boolean {
    if (!isNumericLiteral(node)) {
      return false;
    }

    if (node.parent && isPropertyAssignment(node.parent)) {
      return node.parent.name !== node;
    }

    return true;
  }

  public static convertNumberToExpression(node: Node): Node {
    if (!isNumericLiteral(node)) {
      return node;
    }

    const originNumber: number = Number(node.text);
    if (this.isUnsafeNumber(originNumber)) {
      return node;
    }

    const [intPart, decimalPart] = this.extractIntegerAndDecimalParts(originNumber);

    // split intPart
    const MIN_RANDOM = 0xff;
    const MAX_RIGHT_RANDOM = 0x1fff;
    const randomLeft: number = randomInt(MIN_RANDOM, MAX_RIGHT_RANDOM);
    const randomRight: number = intPart - randomLeft;

    const MAX_LEFT_LEFT_RANDOM = 0xfff;
    const randomLeftLeft: number = randomInt(MIN_RANDOM, MAX_LEFT_LEFT_RANDOM);
    const randomLeftRight: number = randomLeft - randomLeftLeft;

    const leftPartExpression: BinaryExpression = factory.createBinaryExpression(
      factory.createBinaryExpression(
        factory.createNumericLiteral(this.toHexString(randomLeftLeft)),
        SyntaxKind.BarToken,
        factory.createNumericLiteral(this.toHexString(randomLeftRight))
      ),
      SyntaxKind.PlusToken,
      factory.createBinaryExpression(
        factory.createNumericLiteral(this.toHexString(randomLeftLeft)),
        SyntaxKind.AmpersandToken,
        factory.createNumericLiteral(this.toHexString(randomLeftRight))
      )
    );

    const intPartExpression: BinaryExpression = factory.createBinaryExpression(
      leftPartExpression,
      SyntaxKind.PlusToken,
      factory.createNumericLiteral(this.toHexString(randomRight))
    );

    if (decimalPart) {
      return factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          intPartExpression,
          SyntaxKind.PlusToken,
          factory.createNumericLiteral(decimalPart)
        ));
    }

    return factory.createParenthesizedExpression(intPartExpression);
  }

  public static extractIntegerAndDecimalParts(number: number): [number, number | null] {
    const integerPart: number = Math.trunc(number);
    const decimalPart: number | null = number !== integerPart ? number % 1 : null;

    return [integerPart, decimalPart];
  }

  public static isUnsafeNumber(number: number): boolean {
    if (isNaN(number)) {
      return true;
    }

    return number < Number.MIN_SAFE_INTEGER || number > Number.MAX_SAFE_INTEGER;
  }

  public static toHexString(value: number): string {
    const HEX_RADIX = 16;
    if (value > 0) {
      return '0x' + value.toString(HEX_RADIX);
    }

    const absValue: number = Math.abs(value);
    return '-0x' + absValue.toString(HEX_RADIX);
  }
}
