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
    //printf( "%s" EOL, construct );

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
    //printf( "%s" EOL, op );
}
// ====================================================================================================
static void _addRetToStack( RunTime *r, symbolMemaddr p )

{
    if ( r->stackDepth == MAX_CALL_STACK - 1 )
    {
        /* Stack is full, so make room for a new entry */
        memmove( &r->callStack[0], &r->callStack[1], sizeof( symbolMemaddr ) * ( MAX_CALL_STACK - 1 ) );
    }

    r->callStack[r->stackDepth] = p;
    _traceReport( V_DEBUG, "Pushed %08x to return stack", r->callStack[r->stackDepth] );

    if ( r->stackDepth < MAX_CALL_STACK - 1 )
    {
        /* We aren't at max depth, so go ahead and remove this entry */
        r->stackDepth++;
    }
}
// ====================================================================================================
void printCallstack(RunTime *r){
        printf("Callstack with depth %d\n", r->actualCallStack.size());
        // print current stack depth
        int count = 0;
        for (symbolFunctionStore element : r->actualCallStack) {
            for (int j = 0; j < count; j++)
            {
                printf("  ");            
            }
            printf("%s\n", element.funcname);
            count++;
        }
        printf( "\n\n" );
}
void cutoff_first_n_chars(char *str, int n) {
  if (n <= 0 || strlen(str) < n) {
    return; // No characters to cutoff or string shorter than n
  }
  memmove(str, str + n, strlen(str) - n + 1); // Move remaining characters and null terminator
}

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
                    _appendToOPBuffer( r, NULL, r->op.currentLine, LT_EVENT, "========== Exception Entry (%d (%s) at 0x%08x return to %08x ) ==========",
                                       cpu->exception, TRACEExceptionName( cpu->exception ), r->op.workingAddr, cpu->addr );
                    _addRetToStack( r, cpu->addr );
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
                          ( r->op.workingAddr == cpu->addr ) ? "" : "***INCONSISTENT*** ", r->op.workingAddr, cpu->addr );
        }

        /* Return Stack: If we had a stack deletion pending because of a candidate match, it wasn't, so abort */
        if ( r->stackDelPending )
        {
            _traceReport( V_DEBUG, "Stack delete aborted" );
        }

        r->stackDelPending = false;
        /* Whatever the state was, this is an explicit setting of an address, so we need to respect it */
        r->op.workingAddr = cpu->addr;
    }
    else
    {
        /* Return Stack: If we had a stack deletion pending because of a candidate match, the match was good, so commit */
        if ( ( r->stackDelPending == true ) && ( r->stackDepth ) )
        {
            r->stackDepth--;
            _traceReport( V_DEBUG, "Stack delete committed" );
        }

        r->stackDelPending = false;
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

        if ( l )
        {
            /* If we have changed file or function put a header line in */
            if ( l->function )
            {
                /* There is a valid function tag recognised here. If it's a change highlight it in the output. */
                if ( ( l->function->filename != r->op.currentFileindex ) || ( l->function != r->op.currentFunctionptr ) )
                {
                    _appendToOPBuffer( r, l, r->op.currentLine, LT_FILE, "%s::%s", symbolGetFilename( r->s, l->function->filename ), l->function->funcname );
                    r->op.currentFileindex     = l->function->filename;
                    r->op.currentFunctionptr = l->function;
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
            if(insExecuted && ( ic & LE_IC_JUMP )){
                // cutoff first 19 characters
                cutoff_first_n_chars(a, 23);
                char *token; 
                token = strtok(a, " ");
                // do switch case for token
                if(strcmp(token, "bl") == 0)
                {
                    symbolFunctionStore *f = symbolFunctionAt(r->s, newaddr);
                    if(f != NULL)
                    {
                        //printf("Function addded to Callstack: %s\n", f->funcname);
                        r->actualCallStack.push_back(*f);
                        printCallstack(r);
                    }else
                    {
                        //printf("Function addded to Callstack: 0x%08lx\n", newaddr);
                        struct symbolFunctionStore newfunc;
                        newfunc.funcname = "unknown";
                        r->actualCallStack.push_back(newfunc);
                        printCallstack(r);
                    }
                }
                if(strcmp(token,"bx")==0 || strcmp(token,"pop")==0)
                {
                    // check if there are any elements in the call stack
                    if(r->actualCallStack.size() > 0)
                    {
                        //printf("Function removed from Callstack: %s\n", r->actualCallStack.back().funcname);
                        r->actualCallStack.pop_back();
                        printCallstack(r);
                    }else{
                        struct symbolFunctionStore newfunc;
                        newfunc.funcname = "main";
                        r->actualCallStack.push_back(newfunc);
                        printCallstack(r);
                    }
                }
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
                    _addRetToStack( r, r->op.workingAddr + ( ( ic & LE_IC_4BYTE ) ? 4 : 2 ) );
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
                            r->op.workingAddr = r->callStack[r->stackDepth - 1];
                            _traceReport( V_DEBUG, "Return with stacked candidate to %08x", r->op.workingAddr );
                        }
                        else
                        {
                            _traceReport( V_DEBUG, "Return with no stacked candidate" );
                        }

                        r->stackDelPending = true;
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
        }
        else
        {
            _appendToOPBuffer( r, l, r->op.currentLine, LT_ASSEMBLY, "%8x:\tASSEMBLY NOT FOUND" EOL, r->op.workingAddr );
            r->op.workingAddr += 2;
            disposition >>= 1;
            incAddr--;
        }
    }
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