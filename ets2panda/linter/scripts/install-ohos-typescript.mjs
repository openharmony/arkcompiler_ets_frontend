/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import * as fs from 'node:fs'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import { exit } from 'node:process'
import os from 'node:os'
import shell from 'shelljs'

function detectOS() {
    let windowsPlatforms = ['win32', 'win64', 'windows', 'wince']
    let linuxPlatforms = ['linux']
    let detectedOS = null
    const opetaringSystemName = os.platform().toLowerCase()

    if (windowsPlatforms.indexOf(opetaringSystemName) !== -1) {
        detectedOS = 'Windows'
    } else if (linuxPlatforms.indexOf(opetaringSystemName) !== -1) {
        detectedOS = 'Linux'
    }

    return detectedOS
}

function getTypescript(detectedOS) {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    
    const linter = __dirname + '/..'
    const third_party = __dirname + '/../third_party'
    const typescript_dir = third_party + '/third_party_typescript'
    
    if (!fs.existsSync(third_party)) {
        fs.mkdirSync(third_party);
    }

    let branch = process.env.TYPESCRIPT_BRANCH ?? 'master'

    if (detectedOS === 'Linux') {
        if (!fs.existsSync(typescript_dir)) {
            for (let i = 0; i < 5; i++) {
                shell.exec(`git clone --depth=1 https://gitee.com/openharmony/third_party_typescript.git ${typescript_dir}`, { stdio: 'ignore', fatal: true } )
                if (fs.existsSync(typescript_dir)) {
                    break;
                }
            }
        }
        if (!fs.existsSync(typescript_dir)) {
            exit(1)
        }

        shell.cd(typescript_dir)
        shell.exec(`git checkout ${branch}`)
        shell.exec('git pull')
    } else if (detectedOS === 'Windows') {
        if (fs.existsSync(typescript_dir)) {
            fs.rmSync(typescript_dir, {recursive: true, force: true})
        }
        for (let i = 0; i < 5; i++) {
            shell.exec(`git clone --depth=1 --branch=${branch} https://gitee.com/openharmony/third_party_typescript.git ${typescript_dir}`)
            if (fs.existsSync(typescript_dir)) {
                break;
            }
        }
        if (!fs.existsSync(typescript_dir)) {
            exit(1)
        }
        shell.cd(typescript_dir)

        shell.exec('git config core.protectNTFS false')
        shell.exec('git checkout')
    } else {
        console.log('OS was detected, but was not expected')
        exit(1)
    }
    
    const npm_package = shell.exec('npm pack').stdout
    shell.cd(linter)
    shell.exec(`npm install --no-save ${typescript_dir}/${npm_package}`)
    shell.rm(`${typescript_dir}/${npm_package}`)
    
    const node_modules = linter + '/node_modules'
    
    fs.rmSync(node_modules + '/typescript', {recursive: true, force: true})
    fs.cpSync(node_modules + '/ohos-typescript', node_modules + '/typescript', {recursive: true})
}

const detectedOS = detectOS()
if (!detectedOS) {
    console.log('OS was not detected')
    exit(1)
}
getTypescript(detectedOS)

