/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

function destructuringParameters(): void {
  function drawText({ text = '', position: [x, y] = [0, 0] }): void {
    // Draw text
  }
  drawText({ text: 'Figure 1', position: [10, 20] });

  function print([a, b]): void {
    console.log(a, b);
  }
  print(['Hello', 'Wolrd']);

  const hello = ({
    firstName,
    lastName,
  }: {
    firstName: string;
    lastName: string;
  }): string => `Hello ${firstName} ${lastName}`;
  console.log(hello({ firstName: 'Karl', lastName: 'Marks' }));

  const person = { firstName: 'Adam', lastName: 'Smith' };
  console.log(hello(person));
}

function destructuringAssignments(): void {
  let a = 5,
    b = 10,
    c = 'value';
  ({ b, c } = { b: 200, c: 'bar' });
  [a, b] = [b, a];

  const rest: number[];
  [a, b, ...rest] = [10, 20, 30, 40, 50];

  let list = [1, 2];
  list = [...list, 3, 4];

  const e: number;
  let f: number;
  const x: { e: number };
  ({
    a,
    b: {
      c,
      d: [e, f],
    },
  } = { a: 10, b: { c: 'foo', d: [30, 40] } });
  [a, b, [x, { f }]] = [1, 2, [{ e: 20 }, { f: 5 }]];
}

function destructuringDeclarations(): void {
  const { q, w, e } = { q: 1, w: 'foo', e: true };

  function getSomeObject() {
    return { x: 1, y: 2 };
  }
  const { x, y } = getSomeObject();

  const [i, j, k] = [10, 20, 30];

  const getArray = (): number[] => [1, 2, 3];
  const [a, b] = getArray();
}

function loopVariables(): void {
  const objects: { a: number; b: string }[] = [
    { a: 10, b: 'q' },
    { a: 20, b: 'w' },
    { a: 30, b: 'e' },
  ];
  for (const { a, b } of objects) {
    console.log(a, b);
  }

  const arrays = [
    [1, 2],
    [3, 4],
    [5, 6],
  ];
  for (const [q, w] of arrays) {
    console.log(q, w);
  }

  let a: number, b: string;
  for ({ a, b } of objects) {
    console.log(a, b);
  }

  let x: number, y: number;
  for ([x, y] of arrays) {
    console.log(x, y);
  }

  const people = [
    {
      name: 'Mike Smith',
      family: { mother: 'Jane Smith', father: 'Harry Smith' },
    },
    {
      name: 'Tom Jones',
      family: { mother: 'Norah Jones', father: 'Richard Jones' },
    },
  ];
  let n: string, f: string;
  for ({
    name: n,
    family: { father: f },
  } of people) {
    console.log(`Name: ${n}, Father: ${f}`);
  }
}
