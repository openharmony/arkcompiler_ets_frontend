class Person {
    constructor(
        name: string,
        age: number
    ) {}
}
type PersonCtor = new (name: string, age: number) => Person

function createPerson(Ctor: PersonCtor, name: string, age: number): Person
{
    return new Ctor(name, age)
}

const person = createPerson(Person, 'John', 30)