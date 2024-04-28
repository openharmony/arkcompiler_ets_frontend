/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export class MemoryUtils {
  private static baseMemorySize: number | undefined = undefined; 
  private static allowGC: boolean = typeof global.gc === 'function';
  private static MEMORY_BASELINE = 64 * 1024 * 1024; // 64MB
  
  /**
   * Try garbage collection if obfuscaction starts or the memory usage exceeds MEMORY_BASELINE.
   */
  public static tryGC(): void {
    if (!MemoryUtils.allowGC) {
      return;
    }
  
    const currentMemory = process.memoryUsage().heapUsed;
    if (MemoryUtils.baseMemorySize === undefined || (currentMemory - MemoryUtils.baseMemorySize > MemoryUtils.MEMORY_BASELINE)) {
      global.gc();
      MemoryUtils.baseMemorySize = process.memoryUsage().heapUsed;
      return;
    } 

    if (MemoryUtils.baseMemorySize > currentMemory) {
      MemoryUtils.baseMemorySize = currentMemory;
      return;
    }
  }

  // For ut only
  public static setGC(allowGC: boolean): void {
    MemoryUtils.allowGC = allowGC;
  }

  // For ut only
  public static getBaseMemorySize(): number {
    return MemoryUtils.baseMemorySize;
  }

  // For ut only
  public static setBaseMemorySize(baseMemorySize: number | undefined): void {
    MemoryUtils.baseMemorySize = baseMemorySize;
  }

  // For ut only
  public static setBaseLine(baseLine: number): void {
    MemoryUtils.MEMORY_BASELINE = baseLine;
  }
}