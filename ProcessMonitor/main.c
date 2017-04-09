#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "linklist.h"
#include "debuglinklist.h"
#include "global.h"

Kernel_Update * recvlisthead = NULL;
Procmon * proclisthead = NULL;


int main(int argc, char * argv[])
{	
	//initDebugging();
	//return 0;

	HANDLE threads[2];

	HANDLE recvthread = CreateThread(NULL, 0, receiveKernelMessage, NULL, 0, NULL);
	
	HANDLE updatethread = CreateThread(NULL, 0, updateProcList, NULL, 0, NULL);
	if (recvthread)
	{
		printf("Thread created to recv messages");
		threads[0] = recvthread;
	}
	if (updatethread)
	{
		printf("Thead created to update lists");
		threads[1] = updatethread;
	}

	WaitForMultipleObjects(2, threads, TRUE, INFINITE);

	printf("Exiting...");

	return 0;
}