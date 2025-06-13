/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { FileManager } from '../../../src/plugins/FileManager';
import { LANGUAGE_VERSION } from '../../../src/pre_define';
import * as utils from '../../../src/utils';

describe('class FileManager', () => {
    const mockBuildConfig = {
        dependentModuleList: [
            {
                packageName: 'modA',
                modulePath: '/mock/path/modA',
                language: LANGUAGE_VERSION.ARKTS_1_2
            }
        ],
        externalApiPaths: ['/mock/staticApi'],
        buildSdkPath: '/mock/sdk',
        compileFiles: ['/mock/project/main.ets']
    };

    afterEach(() => {
        FileManager.cleanFileManagerObject();
        FileManager.arkTSModuleMap.clear();
        FileManager.staticApiPath.clear();
        FileManager.dynamicApiPath.clear();
        // Make tsc ignore the access of private member
        // @ts-ignore
        FileManager.buildConfig = undefined;
    });

    it('should initialize singleton and static properties', () => {
        FileManager.init(mockBuildConfig as any);
        expect(FileManager.getInstance()).toBeInstanceOf(FileManager);
        expect(FileManager.buildConfig).toEqual(mockBuildConfig);
        expect(FileManager.staticApiPath.size).toBe(1);
        expect(FileManager.dynamicApiPath.size).toBe(2);
        expect(FileManager.arkTSModuleMap.size).toBe(1);
    });

    it('should clean singleton instance', () => {
        FileManager.init(mockBuildConfig as any);
        FileManager.cleanFileManagerObject();
        // Make tsc ignore the access of private member
        // @ts-ignore
        expect(FileManager.instance).toBeUndefined();
    });

    it('should add staticApiPath and dynamicApiPath in initSDK', () => {
        FileManager.initSDK(new Set(['/api1', '/api2']), '/sdk/path');
        expect(FileManager.staticApiPath.has('/api1')).toBe(true);
        expect(FileManager.staticApiPath.has('/api2')).toBe(true);
        expect(FileManager.dynamicApiPath.size).toBe(2);
    });

    it('should handle empty externalApiPath in initSDK', () => {
        FileManager.initSDK(new Set(), '/sdk/path');
        expect(FileManager.staticApiPath.size).toBe(0);
        expect(FileManager.dynamicApiPath.size).toBe(2);
    });

    it('should get correct language version by file path', () => {
        FileManager.init(mockBuildConfig as any);
        const fm = FileManager.getInstance();
        expect(fm.getLanguageVersionByFilePath('/mock/staticApi/abc.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_2);
        const [dynPath] = Array.from(FileManager.dynamicApiPath);
        expect(fm.getLanguageVersionByFilePath(`${dynPath}/abc.ets`)).toBe(LANGUAGE_VERSION.ARKTS_1_1);
        expect(fm.getLanguageVersionByFilePath('/mock/project/main.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_2);
        expect(fm.getLanguageVersionByFilePath('/mock/path/modA/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_2);
        expect(fm.getLanguageVersionByFilePath('/other/path/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_1);
    });

    it('should return ARKTS_1_2 if first line is use static in hybrid module', () => {
        FileManager.init({
            ...mockBuildConfig,
            dependentModuleList: [
                {
                    packageName: 'modH',
                    modulePath: '/mock/hybrid',
                    language: LANGUAGE_VERSION.ARKTS_HYBRID
                }
            ]
        } as any);
        const fm = FileManager.getInstance();
        // Make tsc ignore the access of private member
        // @ts-ignore
        jest.spyOn(FileManager as any, 'isFirstLineUseStatic').mockReturnValue(true);
        expect(fm.getLanguageVersionByFilePath('/mock/hybrid/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_2);
    });

    it('should handle empty dependentModuleList in initLanguageVersionFromDependentModuleMap', () => {
        // Make tsc ignore the access of private member
        // @ts-ignore
        FileManager['initLanguageVersionFromDependentModuleMap']([]);
        expect(FileManager.arkTSModuleMap.size).toBe(0);
    });

    it('should getInstance auto new when not initialized', () => {
        // Make tsc ignore the access of private member
        // @ts-ignore
        FileManager.instance = undefined;
        expect(FileManager.getInstance()).toBeInstanceOf(FileManager);
    });

    it('should return ARKTS_1_1 for hybrid module if first line is not use static', () => {
        FileManager.init({
            dependentModuleList: [
                {
                    packageName: 'modH',
                    modulePath: '/mock/hybrid',
                    language: LANGUAGE_VERSION.ARKTS_HYBRID
                }
            ],
            externalApiPaths: [],
            buildSdkPath: '/mock/sdk',
            compileFiles: []
        } as any);
        const fm = FileManager.getInstance();
        // Make tsc ignore the access of private member
        // @ts-ignore
        jest.spyOn(FileManager as any, 'isFirstLineUseStatic').mockReturnValue(false);
        expect(fm.getLanguageVersionByFilePath('/mock/hybrid/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_1);
    });

    it('should allow cleanFileManagerObject to be called multiple times', () => {
        FileManager.init({
            dependentModuleList: [],
            externalApiPaths: [],
            buildSdkPath: '/mock/sdk',
            compileFiles: []
        } as any);
        FileManager.cleanFileManagerObject();
        expect(FileManager.getInstance()).toBeInstanceOf(FileManager);
        FileManager.cleanFileManagerObject();
        // Make tsc ignore the access of private member
        // @ts-ignore
        expect(FileManager.instance).toBeUndefined();
    });

    it('should return ARKTS_1_1 if staticApiPath and dynamicApiPath are empty', () => {
        FileManager.cleanFileManagerObject();
        FileManager.staticApiPath.clear();
        FileManager.dynamicApiPath.clear();
        FileManager.arkTSModuleMap.clear();
        // Make tsc ignore the access of private member
        // @ts-ignore
        FileManager.buildConfig = { compileFiles: [] };
        const fm = FileManager.getInstance();
        expect(fm.getLanguageVersionByFilePath('/any/path/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_1);
    });

    it('should return module language if not hybrid', () => {
        FileManager.init({
            dependentModuleList: [
                {
                    packageName: 'modB',
                    modulePath: '/mock/path/modB',
                    language: LANGUAGE_VERSION.ARKTS_1_2
                }
            ],
            externalApiPaths: [],
            buildSdkPath: '/mock/sdk',
            compileFiles: []
        } as any);
        const fm = FileManager.getInstance();
        expect(fm.getLanguageVersionByFilePath('/mock/path/modB/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_2);
    });

    it('should isFirstLineUseStatic returns false when first line is not use static', () => {
        jest.spyOn(utils, 'readFirstLineSync').mockReturnValue('not static');
        
        // @ts-ignore
        expect(FileManager['isFirstLineUseStatic']('anyfile.ets')).toBe(false);
    });

    it('should init does nothing if already initialized', () => {
        FileManager.init(mockBuildConfig as any);
        const instance = FileManager.getInstance();
        FileManager.init({
            ...mockBuildConfig,
            buildSdkPath: '/another/path'
        } as any);
        expect(FileManager.getInstance()).toBe(instance);
    });

    it('should cleanFileManagerObject does nothing if instance is undefined', () => {
        // @ts-ignore
        FileManager.instance = undefined;
        expect(() => FileManager.cleanFileManagerObject()).not.toThrow();
    });

    it('should getLanguageVersionByFilePath handles undefined compileFiles', () => {
        FileManager.cleanFileManagerObject();
        // @ts-ignore
        FileManager.buildConfig = {};
        const fm = FileManager.getInstance();
        expect(fm.getLanguageVersionByFilePath('/any/path/file.ets')).toBe(LANGUAGE_VERSION.ARKTS_1_1);
    });

    it('should initSDK handles undefined externalApiPath', () => {
        // @ts-ignore
        expect(() => FileManager.initSDK(undefined, '/sdk/path')).not.toThrow();
    });
});