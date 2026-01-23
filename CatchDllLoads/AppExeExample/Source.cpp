/*
    App to get the DLL example named hola.dll
*/

#include <iostream>
#include <Windows.h>

typedef int (*AddFunc)(int, int); // prototype for the DLL

int main()
{
    std::cout << "This is the begining of something excited!\n";
    AddFunc _AddFunc;

    std::cout << "[.] Loading the DLL\n";
    HINSTANCE hInstLibrary = LoadLibrary(L"hola.dll");

    if (hInstLibrary) {
        std::cout << "[+] DLL Loaded correctly\n";
        _AddFunc = (AddFunc)GetProcAddress(hInstLibrary, "Add");

        if (_AddFunc)
        {
            std::cout << "23 + 43 = " << _AddFunc(23, 43) << std::endl;
        }
        else {
            std::cout << "[!] Error loading Add function\n";
        }

    }
    else {
        std::cout << "[!] Error loading DLL\n";
    }

    std::cin.get();

    if (hInstLibrary) {
        FreeLibrary(hInstLibrary);
        std::cout << "[+] Removing DLL\n";
    }

    std::cout << "[+] Finish program\n";

    return 0;
}
