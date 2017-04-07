#include <stdio.h>
#include <stdlib.h>


//should we hash this for speed?
typedef struct extFileType_t {
	struct extFileType_t* next;
	char* ext;
} extFileType;

typedef struct IOtrace_t {
	struct IOtrace_t* next;
	unsigned word; //use bit wise. to record the action that had happen to it.  Time independed.
	char* filepath;
	char* shadowpath;
} IOtrace;

typedef struct Childproc_t {
	struct Childproc_t* next;
	unsigned int CPID;
	struct Procmon_t* cpnt;
} Childproc;

typedef struct Procmon_t {
	struct Procmon_t* next;
	struct Procmon_t* prev;
	unsigned int PID;
	struct Procmon_t* parent;
	struct Childproc_t* child;
	struct IOtrace_t* IO;
	struct extFileType_t* outExtList;
	struct extFileType_t* inExtList;
	//sumary stats used for heuristics
	unsigned int trustpoints;
	unsigned int delFiles;
	unsigned int touchFiles;
	unsigned int indiffExt;
	unsigned int outdiffExt;
	unsigned int highEntropyFiles;
	unsigned int lowSimilarityScore;
} Procmon;

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