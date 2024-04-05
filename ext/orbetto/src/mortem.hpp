#pragma once

#include "traceDecoder.h"
#include <vector>
#include <protos/perfetto/trace/trace.pb.h>

#define MAX_CALL_STACK (15)
#define DEFAULT_PM_BUFLEN_K (32)

/* Enum for Callstack Properties*/
enum CallStackProperties
{
    FUNCTION,
    EXCEPTION_ENTRY,
    EXCEPTION_EXIT
};

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
    CallStackProperties callStackProperties[MAX_CALL_STACK]; /* Stack of call properties */
    int stackDepth;            
    int exceptionDepth{-1};        
    bool resentStackDel;               /* Possibility to remove an entry from the stack, if address not given */
    bool exceptionEntry{false};
    uint16_t instruction_count{0};
    uint64_t cc{0};
    uint32_t returnAddress{0};
    bool committed{true};
    void (*protobuffCallback)();
    void (*protobuffCycleCount)();
    void (*flushprotobuff)();
};

void dumpElement(RunTime *r, uint8_t element);
void addElementToBuffer(RunTime *r, uint8_t element);
void dumpElementStacked(RunTime *r);
void initialization(RunTime *r);