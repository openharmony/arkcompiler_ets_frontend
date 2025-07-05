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

import chalk from 'chalk';
import * as cliProgress from 'cli-progress';
import type { CmdProgressInfo } from './CmdProgressInfo';

export class FixedLineProgressBar {
  private readonly bar: cliProgress.SingleBar;
  private currentTask: string = '';
  private currentStatus: string = '';
  private isActive = false;
  private lastOutput = '';
  private static fixedLinePosition = 0;

  constructor() {
    this.bar = new cliProgress.SingleBar(
      {
        format: (options, params, payload): string => {
          const bar = options.barCompleteString!.substring(0, Math.round(params.progress * options.barsize!));
          const statusColor =
            payload.status === 'scanning' ? chalk.blue : payload.status === 'fixing' ? chalk.yellow : chalk.green;

          return (
            `${chalk.bold(payload.task)} ${statusColor(payload.statusText)} [${bar}]` +
            `${Math.round(params.progress * 100)}%`
          );
        },
        barCompleteChar: '\u2588',
        barIncompleteChar: '\u2591',
        hideCursor: true,
        clearOnComplete: false,
        stopOnComplete: true,
        linewrap: false,
        forceRedraw: true,
        autopadding: true,
        noTTYOutput: true,
        notTTYSchedule: 0
      },
      cliProgress.Presets.shades_grey
    );
  }

  startBar(taskName: string, total: number, initialStatus: 'scanning' | 'fixing'): void {
    this.isActive = true;
    this.currentTask = taskName;
    this.currentStatus = initialStatus;

    this.bar.start(total, 0, {
      task: `${taskName.padEnd(12)}`,
      status: initialStatus,
      statusText: FixedLineProgressBar.getStatusText(initialStatus)
    });

    this.renderToFixedLine();
  }

  updateBar(progress: number, status: 'scanning' | 'fixing'): void {
    if (!this.isActive) {
      return;
    }

    if (status !== this.currentStatus) {
      this.currentStatus = status;
      this.bar.update(progress, {
        status,
        statusText: FixedLineProgressBar.getStatusText(status)
      });
    } else {
      this.bar.update(progress);
    }

    this.renderToFixedLine();
  }

  completeBar(): void {
    if (!this.isActive) {
      return;
    }

    this.bar.update(this.bar.getTotal(), {
      status: 'completed',
      statusText: 'Completed'
    });

    this.renderToFixedLine();
    this.isActive = false;
  }

  skipBar(): void {
    if (!this.isActive) {
      return;
    }

    this.bar.update(0, {
      status: 'skipped',
      statusText: 'No files need to be fixed --- skipped'
    });

    this.renderToFixedLine();
    this.isActive = false;
  }

  private renderToFixedLine(): void {
    const content = this.bar.lastDrawnString || '';

    FixedLineProgressBar.moveToFixedLine();
    process.stderr.write('\x1B[2K');
    process.stderr.write(content);
    FixedLineProgressBar.restoreCursor();

    this.lastOutput = content;
    FixedLineProgressBar.fixedLinePosition = 1;
  }

  static getStatusText(status: string): string {
    const statusMap: Record<string, string> = {
      scanning: chalk.blue('Scanning...'),
      fixing: chalk.yellow('Fixing...'),
      skipped: chalk.magenta('Skipped'),
      completed: chalk.green('Completed')
    };
    return statusMap[status] || '';
  }

  static moveToFixedLine(): void {
    const linesToMove = FixedLineProgressBar.fixedLinePosition;
    if (linesToMove > 0) {
      process.stderr.write(`\x1B[${linesToMove}F`);
    }
    process.stderr.write('\x1B[0G');
  }

  static restoreCursor(): void {
    const linesToMove = FixedLineProgressBar.fixedLinePosition;
    if (linesToMove > 0) {
      process.stderr.write(`\x1B[${linesToMove}E`);
    }
  }

  stop(): void {
    if (this.isActive) {
      this.isActive = false;
      process.stderr.write('\x1B[1F\x1B[0G\x1B[2K');
    }
  }
}

export function preProcessCmdProgressBar(cmdProgressInfo: CmdProgressInfo): void {
  const { options, cmdProgressBar, srcFiles } = cmdProgressInfo;

  const isMigrationStep = options.migratorMode && cmdProgressInfo.migrationInfo;
  const migrationPhase = isMigrationStep ?
    ` ${cmdProgressInfo.migrationInfo!.currentPass + 1} / ${cmdProgressInfo.migrationInfo!.maxPasses}` :
    '';
  const phasePrefix = isMigrationStep ? 'Migration Phase' : 'Scan Phase';
  const displayContent = `${phasePrefix}${migrationPhase}`;
  const totalFiles = srcFiles.length;

  if (isMigrationStep) {
    cmdProgressBar.startBar(displayContent, totalFiles, 'fixing');
    if (!srcFiles || srcFiles.length === 0) {
      cmdProgressBar.skipBar();
    }
  } else {
    cmdProgressBar.startBar(displayContent, totalFiles, 'scanning');
  }
}

export function processCmdProgressBar(cmdProgressInfo: CmdProgressInfo, fileCount: number): void {
  const progress = fileCount;
  const status = cmdProgressInfo.options.migratorMode && cmdProgressInfo.migrationInfo ? 'fixing' : 'scanning';

  cmdProgressInfo.cmdProgressBar.updateBar(progress, status);
}

export function postProcessCmdProgressBar(cmdProgressInfo: CmdProgressInfo): void {
  const { cmdProgressBar, srcFiles } = cmdProgressInfo;

  if (srcFiles.length > 0) {
    cmdProgressBar.completeBar();

    process.stderr.write('\n');
  } else {
    cmdProgressBar.skipBar();
    process.stderr.write('\n');
  }
}
