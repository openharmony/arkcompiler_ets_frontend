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

export class TimeRecorder {
  private lintStart = BigInt(0);
  private lintEnd = BigInt(0);
  private migrationStart = BigInt(0);
  private migrationEnd = BigInt(0);
  private isHomeCheckCount: boolean = false;

  setHomeCheckCountStatus(isHomeCheckCount: boolean): void {
    this.isHomeCheckCount = isHomeCheckCount;
  }

  getHomeCheckCountStatus(): boolean {
    return this.isHomeCheckCount;
  }

  startScan(): void {
    this.lintStart = process.hrtime.bigint();
  }

  endScan(): void {
    this.lintEnd = process.hrtime.bigint();
  }

  startMigration(): void {
    this.migrationStart = process.hrtime.bigint();
  }

  endMigration(): void {
    this.migrationEnd = process.hrtime.bigint();
  }

  getScanTime(): string {
    return `${(Number(this.lintEnd - this.lintStart) / 1000000000).toFixed(2)} s`;
  }

  getMigrationTime(): string {
    return `${(Number(this.migrationEnd - this.migrationStart) / 1000000000).toFixed(2)} s`;
  }
}
