function foo(): () => int {
    return cb;
}

let cb: () => int = bar;

function bar (): int {
    return 1;
}

function baz(a: () => int): int {
	return a();    
}

function main(): void {
	baz(foo());
}
