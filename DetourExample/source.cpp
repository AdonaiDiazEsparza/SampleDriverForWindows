#include <Windows.h>
#include <iostream>
#include "detours.h"

typedef int(WINAPI* anyfun_t)(int,int);
typedef int(anyfunction)(int, int);

anyfun_t psuma = NULL;

// Funcion
int WINAPI hookSuma(int a, int b)
{
    std::cout << "[=====] Agregando mi codigo UwU\n";
    return psuma(a,b) + 100;
}

int main()
{
    std::cout << "[.] Iniciando programa!\n";

    //anyfunction _resta;
    //anyfunction _multiplicacion;

    std::cout << "[.] Exportando DLL\n";

    HINSTANCE hInstanceDLL = LoadLibrary(L"OperacionesDLL.dll");

    if (!hInstanceDLL) {
        std::cout << "[!] DLL no cargada\n";
        return 1;
    }

    std::cout << "[+] DLL cargada\n";

    anyfunction* suma = (anyfunction*) GetProcAddress(hInstanceDLL, "suma");
    
    if (!suma) {
        FreeLibrary(hInstanceDLL);
        std::cout << "[!] Suma no se pudo resolver\n";
        return 1;
    }

    psuma = suma;

    std::cout << "[.] Hookeando suma\n";

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)psuma, hookSuma);
    DetourTransactionCommit();

    int r = suma(5, 1);

    std::cout << "[.] Resultado de 5 + 1 = " << r << "\n";

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)suma, hookSuma);
    DetourTransactionCommit();

    std::cout << "[+] Removing DLL\n";
    FreeLibrary(hInstanceDLL);
    std::cout << "[+] Finish program\n";

    return 0;
}

