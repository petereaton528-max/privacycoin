/* Fixed trusted bundled Python entry, no PATH search, shell or privileged service. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#ifndef PC_ENTRY
#define PC_ENTRY L"apps\\network_v1\\native_bootstrap.py"
#endif
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,PWSTR arguments,int show) {
    wchar_t root[32768],python[32768],script[32768],command[65536];
    (void)instance;(void)previous;(void)arguments;(void)show;
    DWORD n=GetModuleFileNameW(NULL,root,32768);
    if(!n||n>=32768)goto fail;
    wchar_t *separator=wcsrchr(root,L'\\');if(!separator)goto fail;*separator=0;
    if(_snwprintf(python,32768,L"%ls\\runtime\\python\\pythonw.exe",root)<0||
       _snwprintf(script,32768,L"%ls\\%ls",root,PC_ENTRY)<0||
       _snwprintf(command,65536,L"\"%ls\" -I -S -B \"%ls\"",python,script)<0)goto fail;
    STARTUPINFOW startup={0};PROCESS_INFORMATION child={0};startup.cb=sizeof(startup);
    if(!CreateProcessW(python,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,root,&startup,&child))goto fail;
    CloseHandle(child.hThread);CloseHandle(child.hProcess);return 0;
fail:
    MessageBoxW(NULL,L"The bundled runtime could not start. Preserve your wallet data. Check the verified package and Windows protection history; do not disable security protections.",L"Privacy Coin experimental preview",MB_OK|MB_ICONERROR);return 1;
}
