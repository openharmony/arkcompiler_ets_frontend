export class A {
  constructor(public onAction?: () => void, public onH?: () => void) {}
}

export function f(a: Partial<A>) {}
export function ff(a: A) {}
export function foo(func: () => void) {}
export function bar(func: () => void, a: number, b: string) {}

export class OhosLibC {}
export interface OhosLibI {}
export interface OhosLibIC extends OhosLibC {}
export interface OhosLibII extends OhosLibI {}
export class OhosLibCC extends OhosLibC {}
export class OhosLibCI implements OhosLibI {}

export interface OhosI {
  f: number
}

export function ohFunction1({d: OhosI}): void {} // incorrect usage, but it was an issue, so we check it too
export function ohFunction2(p: {d: OhosI}): void {}

export function fooOh(): any {}
export function barOh(a: any) {}
