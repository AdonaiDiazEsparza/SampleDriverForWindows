/*
    App to get the DLL example named hola.dll
*/

#include <iostream>
#include <Windows.h>

typedef int (*func)(int, int); // prototype for the DLL

int main()
{
    std::cout << "This is the begining of something excited!\n";
    func _AddFunc;

    std::cout << "[.] Loading the DLL\n";
    HINSTANCE hInstLibrary = LoadLibrary(L"hola.dll");

    if (hInstLibrary) {
        std::cout << "[+] DLL Loaded correctly\n";
        _AddFunc = (func)GetProcAddress(hInstLibrary, "suma");

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
