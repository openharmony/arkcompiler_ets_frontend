class Person {
    name: string = ""
    age: number = 0; // semicolon is required here
    [key: string]: string | number
}

const person: Person = {
    name: "John",
    age: 30,
    email: "john@example.com",
    phone: 1234567890,
}