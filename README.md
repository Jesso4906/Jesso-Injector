# Jesso-Injector
C++ console app that can inject a dll into a running process.

A DLL can be injected either by creating a remote thread that calls LoadLibraryA, or by manually mapping the dll into the process memory.
There is also an option to hijack a thread instead of creating a remote thread for both methods.

GUI made using wxWidgets
https://www.wxwidgets.org/
![alt text](https://github.com/Jesso4906/Jesso-Injector/blob/main/screenshot.png)
