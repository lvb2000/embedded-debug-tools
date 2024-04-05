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
#define MAX_BUFFER_SIZE (100)

// Record for options, either defaults or from command line
struct
{
    /* Config information */
    bool useTPIU{true};
    uint32_t tpiuChannel{2};
    uint64_t cps{0};
    std::string file{"./example/trace.tpiu"};
    std::string elfFile{"./example/simple.elf"};
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
    int lastStackDepth{-1};         /* Last stack depth */
    unsigned int lastCycleCount{0};         /* Last cycle count */
    unsigned int lastInterpolation{0};      /* Last interpolation */
    perfetto::protos::FtraceEvent *proto_buffer[MAX_BUFFER_SIZE]; /* Buffer for protobuf */
    uint16_t instruction_counts[MAX_BUFFER_SIZE];          /* Instruction count */
    uint64_t global_interpolations[MAX_BUFFER_SIZE];          /* Global timestamps */
    int proto_buffer_index{0};                    /* Index for the buffer */
} _r;

// Initialize RunTime struct for Mortem
RunTime rt;

// Initialize Protobuf instances
static perfetto::protos::Trace *perfetto_trace;
static perfetto::protos::FtraceEventBundle *ftrace;

// Initialize PID values for Perfetto Traces
static uint32_t activeCallStackThread{500000};
static constexpr uint32_t PID_PC{100000};
static constexpr uint32_t PID_INTERRUPTS{200000};
static constexpr uint32_t PID_CALLSTACK{500000};

// Store interrupt names to give each a unique perfetto thread
static std::unordered_map<uint32_t, char *> interrupt_names;

// Global function declarations
static void _generate_protobuf_entries_single();
static void flush_proto_buffer();
static void _handlePc( struct pcSampleMsg *m, struct ITMDecoder *i );
static void _flushPc();
static void _generate_itm_cycle_counts();

// ====================================================================================================
static void _etmPumpProcessBuffer( uint8_t c)
{
    // pump each individual byte through the ETM decoder
    addElementToBuffer(&rt, c);
    if(rt.wp % 10000==9999) 
    {
        dumpElementStacked(&rt);
    }
}

static void _etmPumpProcessSingle( uint8_t c)
{
    if (rt.cc >=1557814) return;
    //751
    if (rt.cc == 0)
    {
        rt.i.cpu.cycleCount=0;
        _r.timeStamp = 0;
        _r.lastCycleCount = rt.i.cpu.cycleCount;
    }
    // pump each individual byte through the ETM decoder
    dumpElement(&rt, c);
    //750
    if(rt.cc > 0){
        //_generate_protobuf_entries_single();
    }else
    {
        rt.instruction_count = 0;
    }
    if(rt.cc == 1557813 )
    {
        rt.committed = true;
        while(rt.stackDepth >= 0)
        {
            rt.stackDepth--;
            _generate_protobuf_entries_single();
        }
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
                    if ( _r.p.packet[g].s == 2 )
                    {
                        _pumpProcessGeneric( _r.p.packet[g].d );
                        continue;
                    }
                    else if ( _r.p.packet[g].s == 1 )
                    {
                        struct msg p;
                        if ( ITM_EV_PACKET_RXED == ITMPump( &_r.i, _r.p.packet[g].d ) )
                        {
                            if ( ITMGetDecodedPacket( &_r.i, &p )  )
                            {
                                assert( p.genericMsg.msgtype < MSG_NUM_MSGS );
                                if(p.genericMsg.msgtype == MSG_TS)
                                {
                                    struct TSMsg *m = (struct TSMsg *)&p;
                                    _r.timeStamp += m->timeInc;
                                    _flushPc();
                                    _generate_itm_cycle_counts();
                                }
                                else if(p.genericMsg.msgtype == MSG_PC_SAMPLE)
                                {
                                    struct pcSampleMsg *m = (struct pcSampleMsg *)&p;
                                    if(rt.cc > 0)
                                    {
                                        _handlePc(m, &_r.i);
                                    }
                                }else if(p.genericMsg.msgtype == MSG_SOFTWARE)
                                {
                                    struct swMsg *m = (struct swMsg *)&p;
                                    // check on which itm channel the packet has been received
                                    if (m->len > 1)
                                    {
                                        struct symbolFunctionStore *running_func = nullptr;
                                        // check for cycle_count_value
                                        if(m->srcAddr == 5)
                                        {
                                            // create Ftrace event
                                            auto *event = ftrace->add_event();
                                            uint64_t ns = (uint64_t)(((_r.timeStamp * 10e9) / options.cps));
                                            event->set_timestamp(ns);
                                            event->set_pid(PID_PC + 3);
                                            auto *print = event->mutable_print();
                                            char buffer[50];
                                            snprintf(buffer, sizeof(buffer), "I|0|Print: %llu : %llu, %llu", m->value,_r.timeStamp,((m->value * 10e9) / options.cps));
                                            print->set_buf(buffer);
                                        }else{
                                            running_func = symbolFunctionAt( rt.s, m->value );
                                        }
                                        // Begin function
                                        if(m->srcAddr == 1 || m->srcAddr ==3)
                                        {
                                            // create Ftrace event
                                            auto *event = ftrace->add_event();
                                            uint64_t ns = (uint64_t)(((_r.timeStamp * 10e9) / options.cps));
                                            event->set_timestamp(ns);
                                            event->set_pid(PID_PC + 1);
                                            auto *print = event->mutable_print();
                                            char buffer[30];
                                            snprintf(buffer, sizeof(buffer), "B|0|%s", running_func->funcname);
                                            print->set_buf(buffer);
                                        }
                                        else if (m->srcAddr == 2 || m->srcAddr == 4)
                                        {
                                            // create Ftrace event
                                            auto *event = ftrace->add_event();
                                            uint64_t ns = (uint64_t)(((_r.timeStamp * 10e9) / options.cps));
                                            event->set_timestamp(ns);
                                            event->set_pid(PID_PC + 1);
                                            auto *print = event->mutable_print();
                                            char buffer[30];
                                            snprintf(buffer, sizeof(buffer), "E|0|");
                                            print->set_buf(buffer);
                                        }
                                        // Begin function
                                        if(m->srcAddr == 1 || m->srcAddr == 3)
                                        {
                                            // create Ftrace event
                                            auto *event = ftrace->add_event();
                                            uint64_t ns = (uint64_t)(((rt.i.cpu.cycleCount * 10e9) / options.cps));
                                            event->set_timestamp(ns);
                                            event->set_pid(PID_PC + 2);
                                            auto *print = event->mutable_print();
                                            char buffer[30];
                                            snprintf(buffer, sizeof(buffer), "B|0|%s", running_func->funcname);
                                            print->set_buf(buffer);
                                        }
                                        else if (m->srcAddr == 2 || m->srcAddr== 4)
                                        {
                                            // create Ftrace event
                                            auto *event = ftrace->add_event();
                                            uint64_t ns = (uint64_t)(((rt.i.cpu.cycleCount * 10e9) / options.cps));
                                            event->set_timestamp(ns);
                                            event->set_pid(PID_PC + 2);
                                            auto *print = event->mutable_print();
                                            char buffer[30];
                                            snprintf(buffer, sizeof(buffer), "E|0|");
                                            print->set_buf(buffer);
                                        }
                                    }
                                }
                            }
                        }
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

// ====================================================================================================
static void _switchThread(struct symbolFunctionStore *running_func)
{
    if(rt.callStackProperties[rt.stackDepth] == EXCEPTION_ENTRY)
    {
        // add Interrupt name to the map if not already present
        if(!interrupt_names.contains(rt.callStack[rt.stackDepth]))
        {
            if(running_func)
            {
                interrupt_names[rt.callStack[rt.stackDepth]] = running_func->funcname;
            }else
            {
                interrupt_names[rt.callStack[rt.stackDepth]] = "unknown";
            }
        }
        // get index of the interrupt
        int pos = distance(interrupt_names.begin(),interrupt_names.find(rt.callStack[rt.stackDepth]));
        // invert position to get the thread number
        pos = interrupt_names.size() - pos - 1;
        // change thread relative to position in the map
        activeCallStackThread = PID_INTERRUPTS + pos;
    }
}

static void _returnThread(){
    if (rt.stackDepth > 0 && rt.callStackProperties[rt.stackDepth] == EXCEPTION_EXIT)
    {
        activeCallStackThread = PID_CALLSTACK;
    }
}

static void _generate_protobuf_entries_single()
{
    if(rt.cc <= 0) return;
    if(((int)rt.stackDepth != _r.lastStackDepth) && rt.committed)
    {
        // create Ftrace event
        auto *event = ftrace->add_event();
        auto *print = event->mutable_print();
        char buffer[80];
        if(((int)rt.stackDepth > _r.lastStackDepth))
        {
            // get the function at the current address
            struct symbolFunctionStore *running_func = symbolFunctionAt( rt.s, rt.callStack[rt.stackDepth] );
            // check on which thread the event has been received
            _switchThread(running_func);
            // set the pid of the event
            event->set_pid(activeCallStackThread);
            if (running_func)
            {
                snprintf(buffer, sizeof(buffer), "B|0|%s", running_func->funcname);
            }else
            {
                snprintf(buffer, sizeof(buffer), "B|0|0x%08x", rt.op.workingAddr);
            }
        }
        else if(((int)rt.stackDepth < _r.lastStackDepth))
        {
            // set the pid of the event
            event->set_pid(activeCallStackThread);
            // check return to previous thread
            _returnThread();
            snprintf(buffer, sizeof(buffer), "E|0");
        }
        print->set_buf(buffer);
        // as the instruction count interpolation cannot be applied before the next cycle count is received
        // store the event in the buffer
        _r.proto_buffer[_r.proto_buffer_index] = event;
        _r.instruction_counts[_r.proto_buffer_index] = rt.instruction_count;
        _r.global_interpolations[_r.proto_buffer_index] = rt.i.cpu.cycleCount;
        _r.proto_buffer_index++;
        _r.lastStackDepth = rt.stackDepth;
    }
}

static void _generate_protobuf_cycle_counts()
{
    if(rt.cc <= 0) return;
    // create Ftrace event
    auto *event = ftrace->add_event();
    uint64_t ns = (uint64_t)(((rt.i.cpu.cycleCount * 10e9) / options.cps)-1);
    event->set_timestamp(ns);
    event->set_pid(PID_CALLSTACK);
    auto *print = event->mutable_print();
    char buffer[40];
    snprintf(buffer, sizeof(buffer), "I|0|CC: %llu, LC: %llu",rt.i.cpu.cycleCount, rt.cc);
    print->set_buf(buffer);
}

static double _get_ic_percentage(int i)
{
    uint16_t ic = _r.instruction_counts[i];
    double ret = 0;
    if (ic != 0)
    {
            ret = ((double)ic/(double)rt.instruction_count) * (rt.i.cpu.cycleCount - _r.lastCycleCount);
    }
    return ret;
}

static void flush_proto_buffer()
{
    // create Ftrace event
    for (int i = 0; i < _r.proto_buffer_index; i++)
    {
        auto *event = _r.proto_buffer[i];
        uint64_t interpolation = _r.global_interpolations[i] + (uint64_t)_get_ic_percentage(i);
        uint64_t ns = (uint64_t)((interpolation * 10e9) / options.cps);
        event->set_timestamp(ns);  
    }
    // clear buffer after flushing
    _r.proto_buffer_index = 0;
    _r.lastCycleCount = rt.i.cpu.cycleCount;
}
// ====================================================================================================

static bool has_pc_samples{false};
perfetto::protos::FtraceEvent *pc_buffer[MAX_BUFFER_SIZE]; /* Buffer for protobuf */
uint32_t pc_buffer_index{0};
static void _handlePc( struct pcSampleMsg *m, struct ITMDecoder *i )
{
    static uint32_t prev_function_addr{0};
    // Find the function from the PC counter
    if (const auto *function = symbolFunctionAt(rt.s, m->pc); function)
    {
        uint32_t function_addr = function->lowaddr;
        std::string function_name = function->funcname;

        // end the previous function sample
        if(prev_function_addr)
        {
            auto *event = ftrace->add_event();
            event->set_pid(PID_PC);
            auto *print = event->mutable_print();
            char buffer[40];
            snprintf(buffer, sizeof(buffer), "E|0");
            print->set_buf(buffer);
            pc_buffer[pc_buffer_index] = event;
            pc_buffer_index++;
        }
        // start the current function sample
        {
            auto *event = ftrace->add_event();
            event->set_pid(PID_PC);
            auto *print = event->mutable_print();
            char buffer[40];
            snprintf(buffer, sizeof(buffer), "B|0|%s", function_name.c_str());
            print->set_buf(buffer);
            prev_function_addr = function_addr;
            pc_buffer[pc_buffer_index] = event;
            pc_buffer_index++;
        }
    }
}

static void _flushPc()
{
    //printf("Flushing pc buffer: %u\n", pc_buffer_index);
    for (int i = 0; i < pc_buffer_index; i++)
    {
        auto *event = pc_buffer[i];
        uint64_t ns = (_r.timeStamp * 10e9) / options.cps;
        event->set_timestamp(ns);
    }
    pc_buffer_index = 0;
}

static void _generate_itm_cycle_counts()
{
    // create Ftrace event
    auto *event = ftrace->add_event();
    uint64_t ns = (uint64_t)(((_r.timeStamp * 10e9) / options.cps)-1);
    event->set_timestamp(ns);
    event->set_pid(PID_PC);
    auto *print = event->mutable_print();
    char buffer[30];
    snprintf(buffer, sizeof(buffer), "I|0|CC: %llu",_r.timeStamp);
    print->set_buf(buffer);
}


// ====================================================================================================
static void _feedStream()
{
    //---------------- Init perfetto trace ----------------//
    perfetto_trace = new perfetto::protos::Trace();
    auto *ftrace_packet = perfetto_trace->add_packet();
    ftrace_packet->set_trusted_packet_sequence_id(42);
    ftrace_packet->set_sequence_flags(1);
    ftrace = ftrace_packet->mutable_ftrace_events();
    ftrace->set_cpu(0);
    rt.protobuffCallback = _generate_protobuf_entries_single;
    rt.protobuffCycleCount = _generate_protobuf_cycle_counts;
    rt.flushprotobuff = flush_proto_buffer;
    //---------------- Pump data trace ----------------//
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
        while (receivedSize--) _protocolPump(*c++, _etmPumpProcessSingle);
        fflush(stdout);
    }
    stream->close(stream);
    free(stream);
    //---------------- Close all remaining functions in callstack ----------------//
    // rt.committed = true;
    // while(rt.stackDepth > 0)
    // {
    //     rt.stackDepth--;
    //     _generate_protobuf_entries_single();
    // }
    //---------------- Configure PID ----------------//
    auto *packet = perfetto_trace->add_packet();
    packet->set_trusted_packet_sequence_id(42);
    auto *process_tree = packet->mutable_process_tree();
    {
        auto *process = process_tree->add_processes();
        process->set_pid(PID_CALLSTACK);
        process->add_cmdline("CallStack");
    }
    {
        auto *process = process_tree->add_processes();
        process->set_pid(PID_PC);
        process->add_cmdline("PC");
        char buffer[100];
        {
            snprintf(buffer, sizeof(buffer), "PC");
            auto *thread = process_tree->add_threads();
            thread->set_tid(PID_PC);
            thread->set_tgid(PID_PC);
            thread->set_name(buffer);
        }
        {
            snprintf(buffer, sizeof(buffer), "DP-ITM CC");
            auto *thread = process_tree->add_threads();
            thread->set_tid(PID_PC+1);
            thread->set_tgid(PID_PC);
            thread->set_name(buffer);
        }
        {
            snprintf(buffer, sizeof(buffer), "DP-ETM CC");
            auto *thread = process_tree->add_threads();
            thread->set_tid(PID_PC+2);
            thread->set_tgid(PID_PC);
            thread->set_name(buffer);
        }
        {
            snprintf(buffer, sizeof(buffer), "CYCCNT PRINTF");
            auto *thread = process_tree->add_threads();
            thread->set_tid(PID_PC+3);
            thread->set_tgid(PID_PC);
            thread->set_name(buffer);
        }
    }
    {
        auto *process = process_tree->add_processes();
        process->set_pid(PID_INTERRUPTS);
        process->add_cmdline("INTERRUPTS");
        char buffer[100];
        auto p = interrupt_names.begin();
        for(int i=0; i < interrupt_names.size(); i++)
        {
            snprintf(buffer, sizeof(buffer), "%s", p->second);
            auto *thread = process_tree->add_threads();
            thread->set_tid(PID_INTERRUPTS + interrupt_names.size() - i -1);
            thread->set_tgid(PID_INTERRUPTS);
            thread->set_name(buffer);
            p++;
        }
    }
    auto *thread = process_tree->add_threads();
    thread->set_tid(0);
    thread->set_tgid(PID_CALLSTACK);
    //---------------- Generate .perf file ----------------//
    printf("Serializing into 'orbetto.perf'\n");
    std::ofstream perfetto_file("orbetto.perf", std::ios::out | std::ios::binary);
    perfetto_trace->SerializeToOstream(&perfetto_file);
    perfetto_file.close();
    delete perfetto_trace;
}



int main()
{
    initialization(&rt);
    /* Reset the TPIU handler before we start */
    TPIUDecoderInit( &_r.t );
    ITMDecoderInit( &_r.i, true);
    MSGSeqInit( &_r.d, &_r.i, MSG_REORDER_BUFLEN );

    if (options.cps == 0) options.cps = 64000000;

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
    _feedStream();
}