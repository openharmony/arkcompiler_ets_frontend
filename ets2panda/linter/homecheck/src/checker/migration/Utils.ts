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

import { CallGraph, CallGraphBuilder, Scene } from 'arkanalyzer/lib';


export const CALL_DEPTH_LIMIT = 2;
export class CallGraphHelper {
    private static cgInstance: CallGraph | null = null;

    public static getCGInstance(scene: Scene): CallGraph {
        if (!this.cgInstance) {
            this.cgInstance = new CallGraph(scene);
        }
        return this.cgInstance;
    }
}

export class GlobalCallGraphHelper {
    private static cgInstance: CallGraph | null = null;

    public static getCGInstance(scene: Scene): CallGraph {
        if (!this.cgInstance) {
            this.cgInstance = new CallGraph(scene);
            let cgBuilder = new CallGraphBuilder(this.cgInstance, scene);
            cgBuilder.buildDirectCallGraphForScene();
            let entries = this.cgInstance.getEntries().map(funcId => this.cgInstance!.getArkMethodByFuncID(funcId)!.getSignature());
            cgBuilder.buildClassHierarchyCallGraph(entries);
        }
        return this.cgInstance;
    }
}

export const CALLBACK_METHOD_NAME: string[] = [
    "onClick", // 点击事件，当用户点击组件时触发
    "onTouch", // 触摸事件，当手指在组件上按下、滑动、抬起时触发
    "onAppear", // 组件挂载显示时触发
    "onDisAppear", // 组件卸载消失时触发
    "onDragStart", // 拖拽开始事件，当组件被长按后开始拖拽时触发
    "onDragEnter", // 拖拽进入组件范围时触发
    "onDragMove", // 拖拽在组件范围内移动时触发
    "onDragLeave", // 拖拽离开组件范围内时触发
    "onDrop", // 拖拽释放目标，当在本组件范围内停止拖拽行为时触发
    "onKeyEvent", // 按键事件，当组件获焦后，按键动作触发
    "onFocus", // 焦点事件，当组件获取焦点时触发
    "onBlur", // 当组件失去焦点时触发的回调
    "onHover", // 鼠标悬浮事件，鼠标进入或退出组件时触发
    "onMouse", // 鼠标事件，当鼠标按键点击或在组件上移动时触发
    "onAreaChange", // 组件区域变化事件，组件尺寸、位置变化时触发
    "onVisibleAreaChange", // 组件可见区域变化事件，组件在屏幕中的显示区域面积变化时触发
];
