#pragma once

#include "traceDecoder.h"
#include <vector>

#define MAX_CALL_STACK (15)
#define DEFAULT_PM_BUFLEN_K (32)

/* Materials required to be maintained across callbacks for output construction */
struct opConstruct
{
    uint32_t currentFileindex;           /* The filename we're currently in */
    struct symbolFunctionStore *currentFunctionptr;       /* The function we're currently in */
    uint32_t currentLine;                /* The line we're currently in */
    uint32_t workingAddr;                /* The address we're currently in */
};

struct RunTime
{
    enum TRACEprotocol protocol;        /* Encoding protocol to use */
    struct TRACEDecoder i;

    struct symbol *s;                   /* Symbols read from elf */

    uint8_t *pmBuffer;                  /* The post-mortem buffer */
    int pmBufferLen{DEFAULT_PM_BUFLEN_K * 1024};               /* The post-mortem buffer length */
    int wp;
    int rp;

    struct opConstruct op;          /* Materials required to be maintained across callbacks for output construction */

    bool traceRunning;                  /* Set if we are currently receiving trace */
    uint32_t context;                   /* Context we are currently working under */
    symbolMemaddr callStack[MAX_CALL_STACK]; /* Stack of calls */
    unsigned int stackDepth;            /* Maximum stack depth */
    bool stackDelPending;               /* Possibility to remove an entry from the stack, if address not given */
    // global vector for CallStack
    std::vector<symbolFunctionStore> actualCallStack;
};

void dumpElement(RunTime *r, uint8_t element);
void addElementToBuffer(RunTime *r, uint8_t element);
void dumpElementStacked(RunTime *r);
void initialization(RunTime *r);
void clearStack(RunTime *r);