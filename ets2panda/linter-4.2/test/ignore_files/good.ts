export class CGood {}

export type Cb1Good = (a: number, f?: string) => number;
export type Cb2Good = (a: any, f?: string) => number;

export function F1Good(cb?: Cb1Good) {}
export function F2Good(cb?: Cb2Good) {}
