class CustomError extends Error {
    constructor(message?: string) {
        // 'Error' breaks prototype chain here:
        super(message)

        // Restore prototype chain:
        Object.setPrototypeOf(this, new.target.prototype)
    }
}