class Person {
    constructor(
        protected ssn: string,
        private firstName: string,
        private lastName: string
    ) {
        this.ssn = ssn
        this.firstName = firstName
        this.lastName = lastName
    }

    getFullName(): string {
        return this.firstName + " " + this.lastName
    }
}

class Person2{
    protected ssn: string
    private firstName: string
    private lastName: string

    constructor(ssn: string, firstName: string, lastName: string) {
        this.ssn = ssn
        this.firstName = firstName
        this.lastName = lastName
    }

    getFullName(): string {
        return this.firstName + " " + this.lastName
    }
}

class A {
    constructor(readonly a: A) {
      this.a = a;
    }
}
  