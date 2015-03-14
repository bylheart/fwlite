#include "stdafx.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <WinBase.h>
#include <tchar.h>
#include <direct.h>

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
using namespace std;

int main()
{
    TCHAR chpath[MAX_PATH];
    GetModuleFileName(NULL, chpath, MAX_PATH);
    (_tcsrchr(chpath, _T('\\')))[1] = 0;
    SetCurrentDirectoryW(chpath);
    wstring tpath1 = chpath;
    wstring tpath2 = L"Python27\\python27.exe\" -B FW_Lite.pyw";
    tpath1 = tpath1 + tpath2;

    TCHAR path[MAX_PATH] = L"\"";

    for(int i = 1; i < MAX_PATH; i++){
        path[i] = tpath1.c_str()[i-1];
    }
    cout << path << endl;
    STARTUPINFO         sInfo;
    PROCESS_INFORMATION pInfo;

    ZeroMemory(&sInfo, sizeof(sInfo));
    sInfo.cb = sizeof(sInfo);
    sInfo.dwFlags = STARTF_USESHOWWINDOW;
    sInfo.wShowWindow = SW_HIDE;
    ZeroMemory(&pInfo, sizeof(pInfo));

    int result = CreateProcessW(NULL, path, NULL, NULL, false, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);
    return 0;
}
