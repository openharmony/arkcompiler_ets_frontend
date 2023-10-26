function addNumbers(a, b) {
    return a + b;
}

const person1 = {
    firstName: 'John',
    lastName: 'Doe',
    age: 30,
    greet: function () {
        console.log(`Hello, my name is ${this.firstName} ${this.lastName}.`);
    }
};

function findMax(arr) {
    let max = arr[0];
    for (let i = 1; i < arr.length; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

function isPalindrome(str) {
    const cleanStr = str.toLowerCase().replace(/[^a-zA-Z0-9]/g, '');
    const reversedStr = cleanStr.split('').reverse().join('');
    return cleanStr === reversedStr;
}

const person2 = {
    firstName: 'John',
    lastName: 'Doe',
    age: 30,
    greet: function () {
        return `Hello, my name is ${this.firstName} ${this.lastName}.`;
    }
};

function multiplyTable(n) {
    for (let i = 1; i <= 10; i++) {
        console.log(`${n} x ${i} = ${n * i}`);
    }
}

const result = addNumbers(3, 4);

person1.greet();

const numbers = [1, 2, 3, 4, 5];

const sum = numbers.reduce((acc, curr) => acc + curr, 0);

const maxNumber = findMax(numbers);
let i = 1, factorial = 1;
while (i <= 5) {
    factorial *= i;
    i++;
}

const testString = "A man, a plan, a canal: Panama";
const isPalindromic = isPalindrome(testString);

const greeting = person1.greet();

const number = 7;
multiplyTable(number);