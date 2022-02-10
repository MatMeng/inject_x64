# inject_x64
An example of LD_PRELOAD equivalent for Windows x64, which to preload DLLs and override system library functions.

## injectme
An example programme to be injected. This programme only does two things:
- Call ::Sleep() function.
- Print a Hello message to the console.

## spy
This is an example shared library which is going to be injected into "injectme.exe". And while this DLL attaches to a process, it will do the following:
- Redirect stdout to a file named "spy1.log".
- Override ::Sleep() with a function named "hook_Sleep" which will not truely sleep but write a log message instead.

## xstart64
Start a Windows 64-bit programme in the background and inject a 64-bit DLL into the programme at the same time, just like what "LD_PRELOAD" does on Linux. (Support x64 platform only.)

Usage: xstart64.exe <EXE_PATH> <DLL_PATH>

So, try to execute "xstart64.exe injectme.exe spy.dll" and check "spy1.log" to see what happened. Enjoy!
