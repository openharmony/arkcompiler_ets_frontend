from pywinauto.application import Application
import time

def autoburn():
    app = Application(backend = 'uia').start('RKDevTool.exe')
    dlg = app.top_window()
    while True:
        mode = dlg.window(control_type = "Tab").window_text()
        if mode == '发现一个LOADER设备':
            print('start burning')
            dlg.window(title = "执行").click()
            time.sleep(100)
            while True:
                mode = dlg.window(control_type = "Tab").window_text()
                if mode == '发现一个MASKROM设备':
                    dlg.window(title = "关闭").click()
                    print("image burnning finished")
                    return
                else:
                    print("please wait for a while...")
                    time.sleep(5)
        else:
            time.sleep(1)


if __name__ == "__main__":
    autoburn()
        