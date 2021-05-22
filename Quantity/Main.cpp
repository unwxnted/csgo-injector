#include "includes.h"
#include "functions.h"

using namespace std;

void Cleanup(const std::string message) {
    cout << message << std::endl;
    system("pause");
    ExitProcess(0);
}

std::string RandomString(const size_t length)
{
    std::string r;
    static const char bet[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxyzZ1234567890" };
    srand((unsigned)time(NULL) * 5);
    for (int i = 0; i < length; ++i)
        r += bet[rand() % (sizeof(bet) - 1)];
    return r;
}


LPCSTR DLL_NAME;


int main()
{
 
    SetConsoleTitleA(RandomString(32).c_str()); // when starts
    system("Bypass.exe");
    cout << "Welcome to Quantity." << endl;
    cout << "Coded by weakness#0054" << endl << endl;
    cout << "Open the csgo and select your inject method." << endl;
    cout << "Choose the injector mode: " << endl << "1- Load Library" << endl << "2- Manual Map" << endl << "[Quantity]: ";

    int choose;

    cin >> choose;


    cout << "Write the name of the dll: ";
    string DLL;
    cin >> DLL;
    DLL_NAME = DLL.c_str();


    DWORD ProcessId = Functions::FindProcessId("csgo.exe");

    if (!ProcessId)
        Cleanup("No ProcessId Found.");

    SetConsoleTitleA(RandomString(32).c_str()); // when open process and get module address

    HANDLE Game = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    uintptr_t ModuleBase = Functions::GetModuleBaseAddress(ProcessId, "client.dll");




    if (Functions::DoesFileExist(DLL_NAME)) {

        if (!Functions::Internal::ExecuteBypass(Game)) {
            Cleanup("Cannot Bypass...");
        }


        if (choose == 1) {

            SetConsoleTitleA(RandomString(32).c_str()); // when inject

            if (Functions::LoadLibraryInject(ProcessId, DLL_NAME)) {

                Functions::Internal::Backup(Game);
                std::cout << "Injected" << std::endl;
                ExitProcess(0);
            }
            else
            {
                Functions::Internal::Backup(Game);
                Cleanup("Injection Failed.");
            }



        }
        else if (choose == 2) {

            SetConsoleTitleA(RandomString(32).c_str()); // when inject

            if (Functions::ManualMap(DLL_NAME, ProcessId)) {

                Functions::Internal::Backup(Game);
                std::cout << "Injected" << std::endl;
                ExitProcess(0);
            }


        }
        else {
            ExitProcess(0);
        }




    }

    SetConsoleTitleA(RandomString(32).c_str()); // when finish

    return 0;
}