class cls extends Object {
    override toString() : String {
        return "cls";
    }
}

function foo<T>(item : T) : String {
    let str = item.toString();
    return str;
}

function main() : void {
    foo<Int>(10);
    foo<Int>(new Int(20));
    foo<cls>(new cls());
}
