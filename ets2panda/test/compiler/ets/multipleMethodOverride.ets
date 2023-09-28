class A {
    public  foo(): void {

    }
}

class B extends A{
    public override foo(): void{

    }

}

class C extends B{

}

class D extends C {
    public override foo(): void {

    }
}
