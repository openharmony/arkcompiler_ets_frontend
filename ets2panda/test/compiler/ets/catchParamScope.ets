function reject(error: Object): void {
}

function main(): void {
    let fn: () => void = (): void => {
        try {
        } catch (error: Exception) {
            reject(error);
        }
    }
}
