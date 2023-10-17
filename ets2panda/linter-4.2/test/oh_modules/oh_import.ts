export class COh {}

export type Cb1Oh = (a: number, f?: string) => number;
export type Cb2Oh = (a: any, f?: string) => number;

export function F1Oh(cb?: Cb1Oh) {}
export function F2Oh(cb?: Cb2Oh) {}
