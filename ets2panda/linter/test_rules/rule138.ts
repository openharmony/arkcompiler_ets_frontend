type Person = {
    name: string
    age: number
    location: string
}

type QuantumPerson = Omit<Person, "location">

let persons : Record<string, Person> = {
    "Alice": {
        name: "Alice",
        age: 32,
        location: "Shanghai"
    },
    "Bob": {
        name: "Bob",
        age: 48,
        location: "New York"
    }
}
console.log(persons["Bob"].age)
console.log(persons["Rob"].age) // Runtime exception