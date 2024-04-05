#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

#include "git_version_info.h"
#include "generics.h"
#include "nw.h"
#include "traceDecoder.h"
#include "tpiuDecoder.h"
#include "loadelf.h"
#include "sio.h"
#include "stream.h"
#include "mortem.hpp"

#define REMOTE_SERVER       "localhost"

#define SCRATCH_STRING_LEN  (65535)     /* Max length for a string under construction */
//#define DUMP_BLOCK
#define DEFAULT_PM_BUFLEN_K (32)        /* Default size of the Postmortem buffer */
#define MAX_TAGS            (10)        /* How many tags we will allow */

#define INTERVAL_TIME_MS    (1000)      /* Intervaltime between acculumator resets */
#define HANG_TIME_MS        (200)       /* Time without a packet after which we dump the buffer */
#define TICK_TIME_MS        (100)       /* Time intervals for screen updates and keypress check */

// Strdup leak is deliberately ignored. That is the central purpose of this code. It's cleaned
// upin __flushBuffer above.
#pragma GCC diagnostic push
#if !defined(__clang__)
    #pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif

static void _appendToOPBuffer( struct RunTime *r, void *dat, int32_t lineno, enum LineType lt, const char *fmt, ... )

/* Add line to output buffer, in a printf stylee */

{
    char construct[SCRATCH_STRING_LEN];
    va_list va;
    char *p;

    va_start( va, fmt );
    vsnprintf( construct, SCRATCH_STRING_LEN, fmt, va );
    va_end( va );

    /* Make sure we didn't accidentially admit a CR or LF */
    for ( p = construct; ( ( *p ) && ( *p != '\n' ) && ( *p != '\r' ) ); p++ );

    *p = 0;

    
    // printf construct
    printf( "%s" EOL, construct );

}
#pragma GCC diagnostic pop

static void _appendRefToOPBuffer( struct RunTime *r, void *dat, int32_t lineno, enum LineType lt, const char *ref )

/* Add line to output buffer, as a reference (which don't be free'd later) */

{
    // print ref
    //printf( "%s" EOL, ref );
}

// ====================================================================================================
static void _traceReport( enum verbLevel l, const char *fmt, ... )

/* Debug reporting stream */

{
    static char op[SCRATCH_STRING_LEN];
    va_list va;
    va_start( va, fmt );
    vsnprintf( op, SCRATCH_STRING_LEN, fmt, va );
    va_end( va );
    printf( "%s" EOL, op );
}
// ====================================================================================================
uint64_t global_etm_cc = 0;
static void _stackReport(RunTime *r)
{
    if(global_etm_cc < 757)
    {
        return;
    }
    if ( r->stackDepth == 0 )
    {
        //_traceReport( V_DEBUG, "Stack is empty" );
        if(r->callStack[r->stackDepth])
        {
            //printf("Stack %d: %08x\n", r->stackDepth, r->callStack[r->stackDepth]);
        }
        //printf("\n");
    }
    else
    {
        //_traceReport( V_DEBUG, "Stack depth is %d", r->stackDepth );
        /* print current return stack*/
        for ( int i = 0; i < r->stackDepth+1; i++ )
        {
            struct symbolFunctionStore *running_func = symbolFunctionAt( r->s, r->callStack[i] );
            //_traceReport( V_DEBUG, "Stack %d: %08x", i, r->callStack[i] );
            if(running_func)
            {
                //printf("Stack %d: %08x %s\n", i, r->callStack[i], running_func->funcname);
            }
            else
            {
                //printf("Stack %d: %08x\n", i, r->callStack[i]);
            }
        }
        //printf("\n");
    }
}


// ====================================================================================================
static void _addRetToStack( RunTime *r, symbolMemaddr p ,CallStackProperties csp)

{
    if ( r->stackDepth == MAX_CALL_STACK - 1 )
    {
        /* Stack is full, so make room for a new entry */
        memmove( &r->callStack[0], &r->callStack[1], sizeof( symbolMemaddr ) * ( MAX_CALL_STACK - 1 ) );
        memmove( &r->callStackProperties[0], &r->callStackProperties[1], sizeof( CallStackProperties ) * ( MAX_CALL_STACK - 1 ) );
    }
    // check if where are exiting an exception
    if (csp == EXCEPTION_ENTRY)
    {
        r->exceptionDepth = r->stackDepth;
    }

    r->callStack[r->stackDepth] = p;
    _traceReport( V_DEBUG, "Pushed %08x to return stack", r->callStack[r->stackDepth]);

    if ( r->stackDepth < MAX_CALL_STACK - 1 )
    {
        /* We aren't at max depth, so go ahead and remove this entry */
        r->stackDepth++;
    }
    r->callStackProperties[r->stackDepth] = csp;
}
static void _removeRetFromStack(RunTime *r)
{
    if ( r->stackDepth > 0 )
    {
        r->stackDepth--;
        if(r->exceptionDepth >= r->stackDepth)
        {
            r->exceptionDepth = 0;
            r->callStackProperties[r->stackDepth] = EXCEPTION_EXIT;
        }
        _traceReport( V_DEBUG, "Popped %08x from return stack", r->callStack[r->stackDepth]);
    }
}
static void _addTopToStack(RunTime *r,symbolMemaddr p)
{
    if ( r->stackDepth < MAX_CALL_STACK - 1 )
    {
        r->callStack[r->stackDepth] = p;
    }
    r->protobuffCallback();
}
// ====================================================================================================
bool init = false;
int last_stack_depth = -1;
bool revertStack = false;
static void _traceCB( void *d )

/* Callback function for when valid TRACE decode is detected */

{
    RunTime *r = ( RunTime * )d;
    struct TRACECPUState *cpu = TRACECPUState( &r->i );
    uint32_t incAddr = 0;
    uint32_t disposition;
    uint32_t targetAddr = 0; /* Just to avoid unitialised variable warning */
    bool linearRun = false;
    enum instructionClass ic;
    symbolMemaddr newaddr;

    /* Check for Cycle Count update to reset instruction count*/
    if (TRACEStateChanged( &r->i, EV_CH_CYCLECOUNT) )
    {
        r->protobuffCycleCount();
        r->flushprotobuff();
        r->instruction_count = 0;
        //printf("Cycle count reset with: %lu\n",cpu->cycleCount);
    }
    

    /* 2: Deal with exception entry */
    /* ============================ */
    if ( TRACEStateChanged( &r->i, EV_CH_EX_ENTRY ) )
    {
        switch ( r->protocol )
        {
            case TRACE_PROT_ETM4:

                /* For the ETM4 case we get a new address with the exception indication. This address is the preferred _return_ address, */
                /* there will be a further address packet, which is the jump destination, along shortly. Note that _this_ address        */
                /* change indication will be consumed here, and won't hit the test below (which is correct behaviour.                    */
                if ( !TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
                {
                    _traceReport( V_DEBUG, "Exception occured without return address specification" );
                }
                else
                {
                    _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Entry (%d (%s) at 0x%08x return to 0x%08x ) ==========",
                                       cpu->exception, TRACEExceptionName( cpu->exception ), r->op.workingAddr, cpu->addr );
                    r->returnAddress = cpu->addr;
                    revertStack = (cpu->addr != r->callStack[r->stackDepth]);
                    r->exceptionEntry = true;
                }

                break;

            default:
                _traceReport( V_DEBUG, "Unrecognised trace protocol in exception handler" );
                break;
        }
    }


    /* 3: Collect flow affecting changes introduced by this event */
    /* ========================================================== */
    if ( TRACEStateChanged( &r->i, EV_CH_ADDRESS ) )
    {
        /* Make debug report if calculated and reported addresses differ. This is most useful for testing when exhaustive  */
        /* address reporting is switched on. It will give 'false positives' for uncalculable instructions (e.g. bx lr) but */
        /* it's a decent safety net to be sure the jump decoder is working correctly.                                      */

        if ( r->protocol != TRACE_PROT_MTB )
        {
            _traceReport( V_DEBUG, "%sCommanded CPU Address change (Was:0x%08x Commanded:0x%08x)" EOL,
                          ( (r->op.workingAddr == cpu->addr) ||  r->exceptionEntry) ? "" : "***INCONSISTENT*** ", r->op.workingAddr, cpu->addr );
            // Check if because of an exception we need to revert the stack delete because the previous instruction was not executed
            r->committed = true;
            if ( r->resentStackDel && revertStack)
            {
                _traceReport( V_DEBUG, "Stack delete reverted" );
                r->stackDepth++;
            }else
            {
                r->protobuffCallback();
            }
            r->resentStackDel = false;
            // after reverting add the return address of before the exception to the stack
            if( r->exceptionEntry)
            {
                _addRetToStack( r, r->returnAddress ,EXCEPTION_ENTRY);
            }
            r->exceptionEntry = false;
            revertStack = false;
        }
        /* Whatever the state was, this is an explicit setting of an address, so we need to respect it */
        r->op.workingAddr = cpu->addr;
    }
    else
    {
        // Return Stack: If we had a stack deletion pending because of a candidate match, the match was good, so commit
        /*
        if ( ( r->stackDelPending == true ) && ( r->stackDepth ) )
        {
            //r->stackDepth--;
            _traceReport( V_DEBUG, "Stack delete committed" );
            //_stackReport(r);
        }
        r->stackDelPending = false;
        */
        //r->resentStackDel = false;
    }

    // update callstack if stack depth changed when a address has been commanded
    if ( last_stack_depth != r->stackDepth)
    {
        //printf("Stack depth changed from %d to %d\n", last_stack_depth, r->stackDepth);
        last_stack_depth = r->stackDepth;
        _addTopToStack(r,r->op.workingAddr);
        _stackReport(r);
    }
    

    if ( TRACEStateChanged( &r->i, EV_CH_LINEAR ) )
    {
        /* MTB-Specific mechanism: Execute instructions from the marked starting location to the indicated finishing one */
        /* Disposition is all 1's because every instruction is executed.                                                 */
        r->op.workingAddr = cpu->addr;
        targetAddr        = cpu->toAddr;
        linearRun         = true;
        disposition       = 0xffffffff;
        _traceReport( V_DEBUG, "Linear run 0x%08x to 0x%08x" EOL, cpu->addr, cpu->toAddr );
    }

    if ( TRACEStateChanged( &r->i, EV_CH_ENATOMS ) )
    {
        /* Atoms represent instruction steps...some of which will have been executed, some stepped over. The number of steps is the   */
        /* total of the eatoms (executed) and natoms (not executed) and the disposition bitfield shows if each individual instruction */
        /* was executed or not. For ETM3 each 'run' of instructions is a single instruction with the disposition bit telling you if   */
        /* it was executed or not. For ETM4 each 'run' of instructions is from the current address to the next possible change of     */
        /* program flow (and which point the disposition bit tells you if that jump was taken or not).                                */
        incAddr = cpu->eatoms + cpu->natoms;
        disposition = cpu->disposition;
    }

    /* 4: Execute the flow instructions */
    /* ================================ */
    while ( ( incAddr && !linearRun ) || ( ( r->op.workingAddr <= targetAddr ) && linearRun ) )
    {
        /* Firstly, lets get the source code line...*/
        struct symbolLineStore *l = symbolLineAt( r->s, r->op.workingAddr );
        struct symbolFunctionStore *func = symbolFunctionAt( r->s, r->op.workingAddr );

        if ( func )
        {
            /* There is a valid function tag recognised here. If it's a change highlight it in the output. */
            if ( ( func->filename != r->op.currentFileindex ) || ( func != r->op.currentFunctionptr ) )
            {
                _appendToOPBuffer( r, l, r->op.currentLine, LT_FILE, "%s::%s", symbolGetFilename( r->s, func->filename ), func->funcname );
                r->op.currentFileindex     = func->filename;
                r->op.currentFunctionptr = func;
                r->op.currentLine = NO_LINE;
            }
        }
        else
        {
            /* We didn't find a valid function, but we might have some information to work with.... */
            if ( ( NO_FILE != r->op.currentFileindex ) || ( NULL != r->op.currentFunctionptr ) )
            {
                _appendToOPBuffer( r, l, r->op.currentLine, LT_FILE, "Unknown function" );
                r->op.currentFileindex     = NO_FILE;
                r->op.currentFunctionptr = NULL;
                r->op.currentLine = NO_LINE;
            }
        }

        /* If we have changed line then output the new one */
        if ( l && ( ( l->startline != r->op.currentLine ) ) )
        {
            const char *v = symbolSource( r->s, l->filename, l->startline - 1 );
            r->op.currentLine = l->startline;
            _appendRefToOPBuffer( r, l, r->op.currentLine, LT_SOURCE, v );
        }

        /* Now output the matching assembly, and location updates */
        char *a = symbolDisassembleLine( r->s, &ic, r->op.workingAddr, &newaddr );

        if ( a )
        {
            /* Calculate if this instruction was executed. This is slightly hairy depending on which protocol we're using;         */
            /*   * ETM3.5: Instructions are executed based on disposition bit (LSB in disposition word)                            */
            /*   * ETM4  : ETM4 everything up to a branch is executed...decision about that branch is based on disposition bit     */
            /*   * MTB   : Everything except jumps are executed, jumps are executed only if they are the last instruction in a run */
            bool insExecuted = (
                                           /* ETM3.5 case - dependent on disposition */
                                           ( ( !linearRun )  && ( r->i.protocol == TRACE_PROT_ETM35 ) && ( disposition & 1 ) ) ||

                                           /* ETM4 case - either not a branch or disposition is 1 */
                                           ( ( !linearRun ) && ( r->i.protocol == TRACE_PROT_ETM4 ) && ( ( !( ic & LE_IC_JUMP ) ) || ( disposition & 1 ) ) ) ||

                                           /* MTB case - a linear run to last address */
                                           ( ( linearRun ) && ( r->i.protocol == TRACE_PROT_MTB ) &&
                                             ( ( ( r->op.workingAddr != targetAddr ) && ( ! ( ic & LE_IC_JUMP ) ) )  ||
                                               ( r->op.workingAddr == targetAddr )
                                             ) ) );
            _appendToOPBuffer( r, l, r->op.currentLine, insExecuted ? LT_ASSEMBLY : LT_NASSEMBLY, a );
            /* Count instructions fot later interpolating between cycle count packets*/
            if(insExecuted)
            {
                r->instruction_count++;
            }
            /* Move addressing along */
            if ( ( r->i.protocol != TRACE_PROT_ETM4 ) || ( ic & LE_IC_JUMP ) )
            {
                if ( r->i.protocol == TRACE_PROT_ETM4 )
                {
                    _traceReport( V_DEBUG, "Consumed, %sexecuted (%d left)", insExecuted ? "" : "not ", incAddr - 1 );
                }

                disposition >>= 1;
                incAddr--;
            }

            if ( ic & LE_IC_CALL )
            {
                if ( insExecuted )
                {
                    /* Push the instruction after this if it's a subroutine or ISR */
                    _traceReport( V_DEBUG, "Call to %08x", newaddr );
                    _addRetToStack( r, r->op.workingAddr + ( ( ic & LE_IC_4BYTE ) ? 4 : 2 ) ,FUNCTION);
                    //_addTopToStack(r,newaddr);
                    //_stackReport(r);
                }

                r->op.workingAddr = insExecuted ? newaddr : r->op.workingAddr + ( ( ic & LE_IC_4BYTE ) ? 4 : 2 );
            }
            else if ( ic & LE_IC_JUMP )
            {
                _traceReport( V_DEBUG, "%sTAKEN JUMP", insExecuted ? "" : "NOT " );

                if ( insExecuted )
                {
                    /* Update working address according to if jump was taken */
                    if ( ic & LE_IC_IMMEDIATE )
                    {
                        _traceReport( V_DEBUG, "Immediate address %8x", newaddr );
                        /* We have a good address, so update with it */
                        r->op.workingAddr = newaddr;
                    }
                    else
                    {
                        /* We didn't get the address, so need to park the call stack address if we've got one. Either we won't      */
                        /* get an address (in which case this one was correct), or we wont (in which case, don't unstack this one). */
                        if ( r->stackDepth )
                        {
                            r->op.workingAddr= r->callStack[r->stackDepth - 1];
                            _traceReport( V_DEBUG, "Return with stacked candidate to %08x", r->op.workingAddr );
                        }
                        else
                        {
                            _traceReport( V_DEBUG, "Return with no stacked candidate" );
                        }
                        r->committed = false;
                        r->resentStackDel = true;
                        _removeRetFromStack(r);
                    }
                }
                else
                {
                    /* The branch wasn't taken, so just move along */
                    r->op.workingAddr += ( ic & LE_IC_4BYTE ) ? 4 : 2;
                }
            }
            else
            {
                /* Just a regular instruction, so just move along */
                r->op.workingAddr += ( ic & LE_IC_4BYTE ) ? 4 : 2;
            }
            // maybe ad perfetto here on bool function switch
            
        }
        else
        {
            _appendToOPBuffer( r, l, r->op.currentLine, LT_ASSEMBLY, "%8x:\tASSEMBLY NOT FOUND" EOL, r->op.workingAddr );
            r->op.workingAddr += 2;
            disposition >>= 1;
            incAddr--;
        }
        // add current function pointer to the stack if stack depth changed
        if ( last_stack_depth != r->stackDepth)
        {
            //printf("Stack depth changed from %d to %d\n", last_stack_depth, r->stackDepth);
            last_stack_depth = r->stackDepth;
            _addTopToStack(r,r->op.workingAddr);
            _stackReport(r);
        }
    }
    global_etm_cc += 1;
    r->cc = global_etm_cc;
    //printf("Global cycle count %llu\n",global_etm_cc);
}
// ====================================================================================================
void dumpElement( RunTime *r, uint8_t element){
    TRACEDecoderPump( &r->i, &element, 1, _traceCB, r );
}
void addElementToBuffer(RunTime *r, uint8_t element){
    r->pmBuffer[r->wp] = element;
    uint32_t nwp = ( r->wp + 1 ) % r->pmBufferLen;
    if ( nwp == r->rp )
    {
        r->rp = ( r->rp + 1 ) % r->pmBufferLen;
    }
    r->wp = nwp;
}
void dumpElementStacked( RunTime *r){
    TRACEDecoderPump( &r->i, &r->pmBuffer[r->rp], r->pmBufferLen - r->rp, _traceCB, r );
    TRACEDecoderPump( &r->i, &r->pmBuffer[0], r->wp, _traceCB, r );
}
// ====================================================================================================
void initialization(RunTime *r){
    TRACEprotocol trp = TRACE_PROT_ETM4;
    r->protocol = trp;
    r->pmBuffer = ( uint8_t * )calloc( 1, r->pmBufferLen );
    TRACEDecoderInit( &r->i, trp, true, _traceReport );
}