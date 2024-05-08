/* 
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Base class Vehicle
class Vehicle {
    String type;

    public Vehicle(String type) {
        this.type = type;
    }

    public void move() {
        System.out.println("The vehicle is moving.");
    }

    public void startEngine() {
        System.out.println("Starting the engine of a generic vehicle.");
    }
}

// Subclass Car extends Vehicle
class Car extends Vehicle {
    String model;

    public Car(String type, String model) {
        super(type);
        this.model = model;
    }

    public void startEngine() {
        System.out.println("Starting the " + model + " car engine.");
    }

    public void honk() {
        System.out.println("Beep beep! The car is honking.");
    }
}

public class InheritanceTest {
    public static void main(String[] args) {
        // Test the inheritance
        Vehicle vehicle = new Vehicle("Generic");
        vehicle.move();
        vehicle.startEngine();

        Car car = new Car("Sedan", "Toyota Camry");
        car.move();
        car.startEngine();
        car.honk();
    }
}