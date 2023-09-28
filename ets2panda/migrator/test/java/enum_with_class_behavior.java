/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.test.java;

// Enum implements an interface.
// Constants with class body (anonymous class declaration).
interface IOperation {
    int apply (int a, int b);
}
enum ArithmeticOperation implements IOperation {
    PLUS {
        @Override
        public int apply(int a, int b) { return a + b; }
    },
    MINUS {
        @Override
        public int apply(int a, int b) { return a - b; }
    },
    MULTIPLY {
        @Override
        public int apply(int a, int b) { return a * b; }
    },
    DIVIDE {
        @Override
        public int apply(int a, int b) { return a / b; }
    };

    // tests enum instance initializer translation
    // super(name, ordinal) call should be inserted
    // into resulting ctor!
    private String foo;
    { foo = "bar"; }
}

// Enum declaration with type members (ctor, methods, etc).
// Constants are initialized through constructor.
enum Planet {
    MERCURY (3.303e+23, 2.4397e6),
    VENUS   (4.869e+24, 6.0518e6),
    EARTH   (5.976e+24, 6.37814e6),
    MARS    (6.421e+23, 3.3972e6),
    JUPITER (1.9e+27,   7.1492e7, PlanetType.GAS),
    SATURN  (5.688e+26, 6.0268e7, PlanetType.GAS),
    URANUS  (8.686e+25, 2.5559e7, PlanetType.ICE),
    NEPTUNE (1.024e+26, 2.4746e7, PlanetType.ICE);

    enum PlanetType {
        ROCK,
        GAS,
        ICE
    }

    private final double mass;   // in kilograms
    private final double radius; // in meters
    private final PlanetType type;

    Planet(double mass, double radius, PlanetType type) {
        this.mass = mass;
        this.radius = radius;
        this.type = type;
    }

    Planet(double mass, double radius) {
        // No super(name, ordinal) call in translation here!
        this(mass, radius, PlanetType.ROCK);
    }

    // Checks addition of name and ordinal parameters
    // to explcitly-defined parameter-less enum ctor.
    private Planet() {
        mass = 0.;
        radius = 0.;
        type = PlanetType.ROCK;
    }

    // Checks addition of name and ordinal arguments
    // to explicit parameter-less ctor call
    private Planet(double mass) {
        this();
    }

    // universal gravitational constant  (m3 kg-1 s-2)
    public static final double G = 6.67300E-11;

    double surfaceGravity() {
        return G * mass / (radius * radius);
    }

    double surfaceWeight(double otherMass) {
        return otherMass * surfaceGravity();
    }
}
