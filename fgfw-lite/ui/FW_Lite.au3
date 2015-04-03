#-*- coding: UTF-8 -*-
#NoTrayIcon
#region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=taskbar.ico
#endregion ;**** Directives created by AutoIt3Wrapper_GUI ****
FileChangeDir(@ScriptDir)
Run("./Python27/python27.exe -B ./FW_Lite.pyw", @ScriptDir, @SW_HIDE)
Exit
