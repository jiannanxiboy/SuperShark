#pragma once
#include <Windows.h>
#include <cstdio>
#include <string>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <vector>

#include "MiscUtil.h"

#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif

class ProcessUtil {

public:
	static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);

	static int Kill(PID_T pid);

	static bool Exec(std::string command);
};