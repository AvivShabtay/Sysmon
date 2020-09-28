#include "pch.h"
#include "../Sysmon/SysMonCommon.h"
#include <string>
#include <Psapi.h>

// Define prototypes:
int Error(const char* text);
void DisplayTime(const LARGE_INTEGER& time);
void DisplayInfo(BYTE* buffer, DWORD size);

int main() {

	// Acquire device to Sysmon driver:
	HANDLE hSysmonDevice = CreateFile(L"\\\\.\\sysmon", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hSysmonDevice == INVALID_HANDLE_VALUE) {
		return Error("Could not get sysmon device");
	}

	// Buffer for incoming data, 64KB:
	BYTE buffer[1 << 16];

	// Pooling request for data:
	while (true) {
		DWORD dwBytesRead;

		// Request to read data from sysmon driver:
		if (!(::ReadFile(hSysmonDevice, buffer, sizeof(buffer), &dwBytesRead, nullptr))) {
			return Error("Could not read data");
		}

		// Display data if it exist:
		if (dwBytesRead != 0) {
			DisplayInfo(buffer, dwBytesRead);
		}

		// Wait for new events to arrive:
		::Sleep(200);
	}
}

/*
* Get error text, retrieve GetLastError value and prints it.
*/
int Error(const char* text) {
	printf("%s (%d)\n", text, ::GetLastError());
	return 1;
}

/*
* Get LARGE_INTEGER representing time-stamp and prints it.
*/
void DisplayTime(const LARGE_INTEGER& time) {
	SYSTEMTIME st;
	::FileTimeToSystemTime((FILETIME*)&time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

/*
* Get PID, retrieve it's image file path and prints it.
*/
void DisplayProcessNameByPID(const ULONG pid) {
	TCHAR procName[1024];
	HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (hProc == INVALID_HANDLE_VALUE)
		return;

	if (::GetProcessImageFileName(hProc, procName, 1024)) {
		printf("%ws ", procName);
	}

	CloseHandle(hProc);
}

/*
* Accept buffer and size and parse the data to display notifications
* coming from Sysmon driver.
*	buffer	- contain the blob of data read from the Sysmon's device object.
*	size	- the size of the buffer.
* Each data in the buffer is of type ItemHeader.
*/
void DisplayInfo(BYTE* buffer, DWORD size) {
	DWORD count = size;

	while (0 < count) {
		ItemHeader* header = (ItemHeader*)buffer;
		switch (header->Type) {
		case ItemType::ProcessCreate:
		{
			DisplayTime(header->Time);
			ProcessCreateInfo* info = (ProcessCreateInfo*)buffer;
			std::wstring commandLine((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
			printf("Process %d Created. Command line: %ws\n", info->ProcessId, commandLine.c_str());
			break;
		}
		case ItemType::ProcessExit:
		{
			DisplayTime(header->Time);
			ProcessExitInfo* info = (ProcessExitInfo*)buffer;
			printf("Process %d Exited\n", info->ProcessId);
			break;
		}
		case ItemType::ThreadCreate:
		{
			DisplayTime(header->Time);
			ThreadCreateExitInfo* info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Created in process %d ", info->ThreadId, info->ProcessId);
			DisplayProcessNameByPID(info->ProcessId);
			printf("\n");
			break;
		}
		case ItemType::ThreadExit:
		{
			DisplayTime(header->Time);
			ThreadCreateExitInfo* info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Exited in process %d ", info->ThreadId, info->ProcessId);
			DisplayProcessNameByPID(info->ProcessId);
			printf("\n");
			break;
		}
		case ItemType::ImageLoad:
		{
			DisplayTime(header->Time);
			ImageLoadInfo* info = (ImageLoadInfo*)buffer;
			std::wstring imagePath((WCHAR*)(buffer + info->ImagePathOffset), info->ImagePathLength);
			printf("Image loaded into process %d at address 0x%p (%ws)\n", info->ProcessId, info->ImageBage, imagePath.c_str());
			break;
		}
		default:
			break;
		}

		// Move to the next entry in the linked list:
		buffer += header->Size;
		count -= header->Size;
	}
}