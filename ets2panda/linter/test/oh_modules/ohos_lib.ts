export class A {
  constructor(public onAction?: () => void, public onH?: () => void) {}
}

export function f(a: Partial<A>) {}
export function ff(a: A) {}

export class OhosLibC {}
export interface OhosLibI {}
export interface OhosLibIC extends OhosLibC {}
export interface OhosLibII extends OhosLibI {}
export class OhosLibCC extends OhosLibC {}
export class OhosLibCI implements OhosLibI {}
