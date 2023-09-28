interface MyStack<Item> {
    getTop() : Item;
    pop() : Item;
    push(item : Item) : void;
    isEmpty() : boolean;
    size() : int;
}

class MyArrayStack<Item> implements MyStack<Item> {

    private container : Item[];
    private top : int = -1;
    private readonly DEFAULT_SIZE : int = 100;

    constructor() {
        this.container = new Item[this.DEFAULT_SIZE];
        this.top = -1;
    }

    constructor(size: int) {
        this.container = new Item[size];
    }

    override getTop() : Item {
        if (this.top == -1) {
            return null;
        }
        return this.container[this.top];
    }

    override pop() : Item {
        if (this.top == -1) {
            return null;
        }
        return this.container[this.top--];
    }

    override push(item : Item) : void {
        this.container[++this.top] = item;
    }

    override isEmpty() : boolean {
        return (this.top == -1);
    }

    override size() : int {
        return (this.top + 1);
    }
}

function main() : void {
  let stack1 : MyArrayStack<Int>;
  stack1 = new MyArrayStack<Int>();
  assert(stack1.isEmpty() == true);
  assert(stack1.size() == 0);

  stack1.push(new Int(10));
  assert(stack1.isEmpty() == false);
  assert(stack1.size() == 1);
  assert((stack1.getTop() as Int) == 10);

  stack1.push(new Int(20));
  stack1.push(new Int(30));
  assert(stack1.isEmpty() == false);
  assert(stack1.size() == 3);
  assert((stack1.getTop() as Int) == 30);

  assert((stack1.pop() as Int) == 30);
  assert(stack1.size() == 2);
  assert((stack1.pop() as Int) == 20);
  assert(stack1.size() == 1);
  assert((stack1.pop() as Int) == 10);
  assert(stack1.size() == 0);
  assert(stack1.isEmpty() == true);

  assert(stack1.getTop() == null);
  assert(stack1.pop() == null);
  assert(stack1.size() == 0);
  assert(stack1.isEmpty() == true);

}
