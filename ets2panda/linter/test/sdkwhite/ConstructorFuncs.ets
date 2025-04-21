/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// 1. First, define the DatabaseObject base class and several entity classes

// Base database object interface
interface DatabaseObject {
  id: number;
  save(): Promise<void>;
}

// User entity class
class User implements DatabaseObject {
  id: number;
  username: string;
  email: string;

  constructor() {
    this.id = 0;
    this.username = '';
    this.email = '';
  }

  async save(): Promise<void> {
    console.log(`Saving user ${this.username}`);
    // Actual saving logic...
  }
}

// Product entity class
class Product implements DatabaseObject {
  id: number;
  name: string;
  price: number;

  constructor() {
    this.id = 0;
    this.name = '';
    this.price = 0;
  }

  async save(): Promise<void> {
    console.log(`Saving product ${this.name}`);
    // Actual saving logic...
  }
}

// 2. Implement the DatabaseQuery class
class DatabaseQuery<T extends DatabaseObject> {
  private entityClass: new () => T;

  constructor(entityClass: new () => T) {
    this.entityClass = entityClass;
  }

  // Example query method
  async findById(id: number): Promise<T | null> {
    const entity = new this.entityClass();
    // Simulate database query
    console.log(`Querying ${entity.constructor.name} with id ${id}`);
    // Actual query logic...
    return {...entity, id}; // Return simulated data
  }

  // Another example query method
  async findAll(): Promise<T[]> {
    const entity = new this.entityClass();
    console.log(`Querying all ${entity.constructor.name} records`);
    // Actual query logic...
    return [{...entity, id: 1}]; // Return simulated data
  }
}

// 3. Usage example

// Create a user query instance
const userQuery = new DatabaseQuery(User); // Error occurs

// Use the query methods
(async () => {
  const user = await userQuery.findById(1);
  if (user) {
    console.log(`Found user: ${user.username}`);
    user.username = "newUsername";
    await user.save();
  }

  const allUsers = await userQuery.findAll();
  console.log(`Found ${allUsers.length} users`);

  // Create a product query instance
  const productQuery = new DatabaseQuery(Product); // Error occurs
  const product = await productQuery.findById(5);
  if (product) {
    console.log(`Found product: ${product.name} ($${product.price})`);
  }
})();