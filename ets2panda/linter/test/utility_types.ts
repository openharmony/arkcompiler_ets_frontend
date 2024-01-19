/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

function awaitedType(): void {
  type A = Awaited<Promise<string>>;

  type B = Awaited<Promise<Promise<number>>>;

  type C = Awaited<boolean | Promise<number>>;
}

function requiredType(): void {
  interface Props {
    a?: number;
    b?: string;
  }

  const obj: Props = { a: 5 };
  const obj2: Required<Props> = { a: 5, b: 'text' };
}

function readonlyType(): void {
  interface Todo {
    title: string;
  }

  const todo: Readonly<Todo> = {
    title: 'Delete inactive users',
  };

  console.log(todo.title);
}

function pickType(): void {
  interface Todo {
    title: string;
    description: string;
    completed: boolean;
  }

  type TodoPreview = Pick<Todo, 'title' | 'completed'>;

  const todo: TodoPreview = {
    title: 'Clean room',
    completed: false,
  };

  console.log(todo);
}

function omitType(): void {
  interface Todo {
    title: string;
    description: string;
    completed: boolean;
    createdAt: number;
  }

  type TodoPreview = Omit<Todo, 'description'>;

  const todo: TodoPreview = {
    title: 'Clean room',
    completed: false,
    createdAt: 1615544252770,
  };

  console.log(todo);

  type TodoInfo = Omit<Todo, 'completed' | 'createdAt'>;

  const todoInfo: TodoInfo = {
    title: 'Pick up kids',
    description: 'Kindergarten closes at 5pm',
  };

  console.log(todoInfo);
}

function excludeType(): void {
  type T0 = Exclude<'a' | 'b' | 'c', 'a'>;

  type T1 = Exclude<'a' | 'b' | 'c', 'a' | 'b'>;

  type T2 = Exclude<string | number | (() => void), Function>;
}

function extractType(): void {
  type T0 = Extract<'a' | 'b' | 'c', 'a' | 'f'>;

  type T1 = Extract<string | number | (() => void), Function>;
}

function nonNullableType(): void {
  type T0 = NonNullable<string | number | undefined>;

  type T1 = NonNullable<string[] | null | unknown>;
}

function parametersType(): void {
  function f1(arg: { a: number; b: string }): void {
    arg.a++;
  }

  type T0 = Parameters<() => string>;

  type T1 = Parameters<(s: string) => void>;

  type T2 = Parameters<<T>(arg: T) => T>;

  type T3 = Parameters<typeof f1>;

  type T4 = Parameters<any>;

  type T5 = Parameters<never>;
}

function constructorParametersType(): void {
  type T0 = ConstructorParameters<ErrorConstructor>;

  type T1 = ConstructorParameters<FunctionConstructor>;

  type T2 = ConstructorParameters<RegExpConstructor>;

  type T3 = ConstructorParameters<any>;
}

function returnType(): void {
  function f1(): { a: number; b: string } {
    return { a: 10, b: '20' };
  }

  type T0 = ReturnType<() => string>;

  type T1 = ReturnType<(s: string) => void>;

  type T2 = ReturnType<<T>() => T>;

  type T3 = ReturnType<<T extends U, U extends number[]>() => T>;

  type T4 = ReturnType<typeof f1>;

  type T5 = ReturnType<any>;

  type T6 = ReturnType<never>;
}

function instanceType(): void {
  class C {
    x = 0;
    y = 0;
  }

  type T0 = InstanceType<typeof C>;

  type T1 = InstanceType<any>;

  type T2 = InstanceType<never>;
}

function thisParameterType(): void {
  function toHex(this: number) {
    return this.toString(16);
  }

  function numberToString(n: ThisParameterType<typeof toHex>) {
    return toHex.apply(n);
  }
}

function omitThisParameterType(): void {
  function toHex(this: number) {
    return this.toString(16);
  }

  const fiveToHex: OmitThisParameter<typeof toHex> = toHex.bind(5);

  console.log(fiveToHex());
}

function thisType(): void {
  type ObjectDescriptor<D, M> = {
    data?: D;
    methods?: M & ThisType<D & M>; // Type of 'this' in methods is D & M
  };

  function makeObject<D, M>(desc: ObjectDescriptor<D, M>): D & M {
    const data: object = desc.data || {};
    const methods: object = desc.methods || {};
    return { ...data, ...methods } as D & M;
  }

  const obj = makeObject({
    data: { x: 0, y: 0 },
    methods: {
      moveBy(dx: number, dy: number) {
        this.x += dx; // Strongly typed this
        this.y += dy; // Strongly typed this
      },
    },
  });

  obj.x = 10;
  obj.y = 20;
  obj.moveBy(5, 5);
}

function uppercaseType(): void {
  type Greeting = 'Hello, world';
  type ShoutyGreeting = Uppercase<Greeting>;

  type ASCIICacheKey<Str extends string> = `ID-${Uppercase<Str>}`;
  type MainID = ASCIICacheKey<'my_app'>;
}

function lovercaseType(): void {
  type Greeting = 'Hello, world';
  type QuietGreeting = Lowercase<Greeting>;

  type ASCIICacheKey<Str extends string> = `id-${Lowercase<Str>}`;
  type MainID = ASCIICacheKey<'MY_APP'>;
}

function capitalizeType(): void {
  type LowercaseGreeting = 'hello, world';
  type Greeting = Capitalize<LowercaseGreeting>;
}

function uncapitalizeType(): void {
  type UppercaseGreeting = 'HELLO WORLD';
  type UncomfortableGreeting = Uncapitalize<UppercaseGreeting>;
}
