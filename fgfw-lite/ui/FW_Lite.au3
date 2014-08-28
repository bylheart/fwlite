#-*- coding: UTF-8 -*-
#NoTrayIcon
#region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=taskbar.ico
#endregion ;**** Directives created by AutoIt3Wrapper_GUI ****

setEnv()
Run("./Python27/python27.exe -B ./FW_Lite.pyw", @ScriptDir, @SW_HIDE)
Exit

Func setEnv()
	If StringInStr(@ScriptDir, " ") Then
		MsgBox(16, "FGFW_Lite", "路径中不允许有空格，FGFW_Lite将退出！", 5)
		Exit (1)
	EndIf
EndFunc   ;==>setEnv
