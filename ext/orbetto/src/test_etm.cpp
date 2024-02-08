#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <assert.h>
#include <inttypes.h>
#include <getopt.h>
#include <time.h>
#include <set>
#include <iostream>
#include <fstream>

using namespace std::string_literals;

#include "tpiuDecoder.h"
#include "itmDecoder.h"
#include "msgDecoder.h"

#include "nw.h"
#include "git_version_info.h"
#include "generics.h"
#include "msgSeq.h"
#include "stream.h"
#include "loadelf.h"
#include "device.hpp"

// custom cutdown mortem
#include "mortem.hpp"

// To get the ITM channel list
#include "../../src/emdbg/patch/data/itm.h"

#include <protos/perfetto/trace/trace.pb.h>

#define MSG_REORDER_BUFLEN  (10)          /* Maximum number of samples to re-order for timekeeping */

// Record for options, either defaults or from command line
struct
{
    /* Config information */
    bool useTPIU{true};
    uint32_t tpiuChannel{2};
    uint64_t cps{0};
    std::string file{"./src/trace.tpiu"};
    std::string elfFile{"./src/simple.elf"};
    bool outputDebugFile;
} options;

struct
{
    /* The decoders and the packets from them */
    struct ITMDecoder i;
    struct MSGSeq    d;
    struct ITMPacket h;
    struct TPIUDecoder t;
    struct TPIUPacket p;
    uint64_t timeStamp;                  /* Latest received time */
    uint64_t ns;                         /* Latest received time in ns */
    struct symbol *symbols;              /* symbols from the elf file */
    unsigned long int lastAddr{0};          /* Last address in callstack */
    unsigned int lastStackDepth{0};         /* Last stack depth */
} _r;

RunTime rt;

// ====================================================================================================
static void _etmPumpProcess( uint8_t c)
{
    // pump each individual byte through the ETM decoder
    addElementToBuffer(&rt, c);
    if(rt.wp % 10000==9999) 
    {
        dumpElementStacked(&rt);
    }

}

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
// Protocol pump for decoding messages
// ====================================================================================================
// ====================================================================================================
// ====================================================================================================
static void _protocolPump( uint8_t c , void ( *_pumpProcessGeneric )( uint8_t ))
{
    if ( options.useTPIU )
    {
        TPIUPumpEvent event = TPIUPump( &_r.t, c );
        // printf("TPIU event: %d\n", event);
        switch ( event )
        {
            case TPIU_EV_NEWSYNC:
            case TPIU_EV_SYNCED:
                ITMDecoderForceSync( &_r.i, true );
                break;
            case TPIU_EV_RXING:
            case TPIU_EV_NONE:
                break;
            case TPIU_EV_UNSYNCED:
                ITMDecoderForceSync( &_r.i, false );
                break;
            case TPIU_EV_RXEDPACKET:
                if ( !TPIUGetPacket( &_r.t, &_r.p ) )
                {
                    genericsReport( V_WARN, "TPIUGetPacket fell over" EOL );
                }
                for ( uint32_t g = 0; g < _r.p.len; g++ )
                {
                    if ( _r.p.packet[g].s == options.tpiuChannel )
                    {
                        _pumpProcessGeneric( _r.p.packet[g].d );
                        continue;
                    }
                    if  ( _r.p.packet[g].s != 0 )
                    {
                        genericsReport( V_DEBUG, "Unknown TPIU channel %02x" EOL, _r.p.packet[g].s );
                    }
                }
                break;
            case TPIU_EV_ERROR:
                genericsReport( V_WARN, "****ERROR****" EOL );
                break;
            default:
                break;
        }
    }
}



int main()
{
    initialization(&rt);
    /* Reset the TPIU handler before we start */
    TPIUDecoderInit( &_r.t );
    ITMDecoderInit( &_r.i, true);
    MSGSeqInit( &_r.d, &_r.i, MSG_REORDER_BUFLEN );

    // check if elf files exists
    assert(std::filesystem::exists(options.elfFile));
    rt.s = symbolAcquire((char*)options.elfFile.c_str(), true, true);
    assert( rt.s );
    printf("Loaded ELF with %u sections:\n", rt.s->nsect_mem);
    for (int ii = 0; ii < rt.s->nsect_mem; ii++)
    {
        auto mem = rt.s->mem[ii];
        printf("  Section '%s': [0x%08lx, 0x%08lx] (%lu)\n", mem.name, mem.start, mem.start + mem.len, mem.len);
    }
    assert(std::filesystem::exists(options.file));
    struct Stream *stream = streamCreateFile( options.file.c_str() );
    while ( true )
    {
        size_t receivedSize;
        struct timeval t;
        unsigned char cbw[TRANSFER_SIZE];
        t.tv_sec = 0;
        t.tv_usec = 10000;
        enum ReceiveResult result = stream->receive( stream, cbw, TRANSFER_SIZE, &t, &receivedSize );
        if (result == RECEIVE_RESULT_EOF or result == RECEIVE_RESULT_ERROR) break;

        uint8_t *c = cbw;
        while (receivedSize--) _protocolPump(*c++, _etmPumpProcess);
        fflush(stdout);
    }
    stream->close(stream);
    free(stream);
}