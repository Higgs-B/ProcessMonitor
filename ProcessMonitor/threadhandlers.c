#include "global.h"

extern Kernel_Update * recvlisthead;
extern Procmon * proclisthead;

DWORD WINAPI receiveKernelMessage() 
{

	int recvmsg = 1;
	Kernel_Update * node;

	//Need some way to know when/where kernel message occurs
	while (1)
	{
		if (recvmsg)
		{
			//Space for update
			node = calloc(sizeof(Kernel_Update), 1);
			//Fill in update
			setKernelUpdateParams(node);
			//Put update at back of recv list
			addLastKernelList(&recvlisthead, node);
			//1 update/sec for testing
			Sleep(1000); 
		}
	}

	return 0;
}

DWORD WINAPI updateProcList() 
{
	Kernel_Update * update_node;
	Procmon * proc_node;
	while (1)
	{
		if (recvlisthead != NULL)
		{
			update_node = recvlisthead;
			//Search proclist for PID of recv_node
			proc_node = findSortProclist(&proclisthead, update_node->PID);
			//if PID not found, calloc space, else apply updates directly
			if (!proc_node)
			{
				proc_node = calloc(sizeof(Procmon), 1);
				initializeProcNode(proc_node, update_node->PID);

				//put new node into list
				addSortProclist(&proclisthead, proc_node);
			}
			//apply updates
			updateProclist(update_node, proc_node);

			//Check for maliciousness
		}
	}


	return 0;
}

void setKernelUpdateParams(Kernel_Update * node) 
{	//Increments all the counters, emulates a doc being "locked."
	node->PID = rand();
	node->Parent_PID = rand();
	node->add_delFiles = 1;
	node->add_highEntropyFiles = 1;
	node->add_lowSimilarityScore = 1;
	node->del_trustpoints = 10;
	node->extin = "doc";
	node->extout = "locked";
	node->add_touchFiles = 1;
	node->next = NULL;
}

void addLastKernelList(Kernel_Update ** head, Kernel_Update* node)
{
	if (!head)
		return;

	if (!node)
		return;

	if (!(*head))
	{
		*head = node;
		return;
	}
	Kernel_Update* cpnt = *head;
	while (cpnt->next)
	{
		cpnt = cpnt->next;
	}
	cpnt->next = node;
	return;
}


Procmon* findSortProclist(Procmon** head, unsigned int PID)
{
	if (!head)
		return 0;

	if (PID <= 0)
		return 0;

	Procmon* cpnt = *head;
	while (cpnt)
	{
		if (cpnt->PID == PID)
		{
			return cpnt;
		}
		cpnt = cpnt->next;
	}
	return 0;
}

void addSortProclist(Procmon** head, Procmon* node)
{
	if (!head)
		return;

	if (!node)
		return;

	if (node->PID <= 0)
		return;

	if (!(*head))
	{
		*head = node;
		return;
	}
	Procmon* ppnt = 0;
	Procmon* cpnt = *head;

	while (cpnt)
	{
		if (node->PID >= cpnt->PID)
		{
			break;
		}
		ppnt = cpnt;
		cpnt = cpnt->next;
	}
	if (ppnt)
	{
		ppnt->next = node;
		node->next = cpnt;
	}
	else { //this can only happen if the node is greater than the head
		node->next = *head;
		*head = node;
	}
}

void initializeProcNode(Procmon *proc_node, unsigned int PID)
{
	proc_node->child = NULL;
	proc_node->delFiles = 0;
	proc_node->highEntropyFiles = 0;
	proc_node->indiffExt = 0;
	proc_node->inExtList = NULL;
	proc_node->IO = NULL;
	proc_node->lowSimilarityScore = 0;
	proc_node->next = NULL;
	proc_node->outdiffExt = 0;
	proc_node->outExtList = NULL;
	proc_node->parent = NULL;
	proc_node->PID = PID;
	proc_node->touchFiles = 0;
	proc_node->trustpoints = 100;
}

void updateProclist(Kernel_Update * update_node,Procmon * proc_node)
{
	Procmon * parent_node;

	//Update counters
	proc_node->trustpoints -= update_node->del_trustpoints;
	proc_node->delFiles += update_node->add_delFiles;
	proc_node->touchFiles += update_node->add_touchFiles;
	proc_node->highEntropyFiles += update_node->add_highEntropyFiles;
	proc_node->lowSimilarityScore += update_node->add_lowSimilarityScore;

	//Check for parent to exist and NOT BE FOUND already
	if ((update_node->Parent_PID != 0) && (proc_node->parent == NULL))
	{
		//Update proc_node accordingly if parent is found
		parent_node = findSortProclist(&proclisthead, update_node->Parent_PID);
		proc_node->parent = parent_node;
	}
	
}


typedef struct Kernel_Update_t {
	struct Kernel_Update_t* next;
	struct IOtrace_t * IO;//?
	unsigned int PID;
	unsigned int Parent_PID;
	unsigned int del_trustpoints;
	unsigned int add_delFiles;
	unsigned int add_touchFiles;
	char * extin;
	char * extout;
	unsigned int add_highEntropyFiles;
	unsigned int add_lowSimilarityScore;
} Kernel_Update;