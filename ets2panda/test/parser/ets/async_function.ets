class Class {
    public async bar(): Promise<Object> | null { return null; }
}

async function foo(): Promise<Object> | null { return null; }

let lambda: () => Promise<Object> | null = async (): Promise<Object> | null => { return null; }
