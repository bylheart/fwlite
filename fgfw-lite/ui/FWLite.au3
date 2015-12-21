#-*- coding: UTF-8 -*-
#NoTrayIcon
#region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=taskbar.ico
#endregion ;**** Directives created by AutoIt3Wrapper_GUI ****
FileChangeDir(@ScriptDir)
Run("./Python27/pythonw27.exe -B ./FWLite.pyw", @ScriptDir)
Exit
