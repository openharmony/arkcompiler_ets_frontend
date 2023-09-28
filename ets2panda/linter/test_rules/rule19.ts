interface Identity {
    id: number
    name: string
}

interface Contact {
    email: string
    phone: string
}

type Employee = Identity & Contact

interface Employee2 extends Identity,  Contact {}