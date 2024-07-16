# ====================================================================
define orbuculum
  help orbuculum
end
document orbuculum
GDB SWO Trace Configuration Helpers
===================================

Setup Device
------------
STM32;
  enableSTM32SWO  : Enable SWO on STM32 pins (for F4 or F7 if 4/7 is passed as first argument)
  enableSTM32TRACE: Start TRACE on STM32 pins

IMXRT;
  enableIMXRT102XSWO  : Enable SWO on IMXRT102X series pins (AD_B0_04)
  enableIMXRT102XTRACE: Start TRACE on IMXRT102X series pins
  enableIMXRT106XSWO  : Enable SWO on IMXRT106X series pins (AD_B0_10)

SAM5X;
  enableSAMD5XSWD    : Enable SWO on SAM5X output pin on SAM5X

NRF;
  enableNRF52TRACE : Start TRACE on NRF52 (not nrf52833 or nrf52840) pins
  enableNRF53TRACE : Start TRACE on NRF53* pins

EFR32MG12;
  enableEFR32MG12SWO : Start SWO on EFR32MG12 pins

TM4C;
  enableTM4C123TRACE : Start TRACE on TM4C123 pins (defaults to 2 pin mode as 4 pin trace is unavailable on all)

All;
  prepareSWO      : Prepare SWO output in specified format
  startETM        : Start ETM output on channel 2

Configure DWT
-------------
dwtPOSTCNT        : Enable POSTCNT underflow event counter packet generation
dwtFOLDEVT        : Enable folded-instruction counter overflow event packet generation
dwtLSUEVT         : Enable LSU counter overflow event packet generation
dwtSLEEPEVT       : Enable Sleep counter overflow event packet generation
dwtDEVEVT         : Enable Exception counter overflow event packet generation
dwtCPIEVT         : Enable CPI counter overflow event packet generation
dwtTraceException : Enable Exception Trace Event packet generation
dwtSamplePC       : Enable PC sample using POSTCNT interval
dwtSyncTap        : Set how often Sync packets are sent out (None, CYCCNT[24], CYCCNT[26] or CYCCNT[28])
dwtPostTap        : Sets the POSTCNT tap (CYCCNT[6] or CYCCNT[10])
dwtPostInit       : Sets the initial value for the POSTCNT counter
dwtPostReset      : Sets the reload value for the POSTCNT counter
dwtCycEna         : Enable or disable CYCCNT

Configure ITM
-------------
ITMId             : Set the ITM ID for this device
ITMGTSFreq        : Set Global Timestamp frequency
ITMTSPrescale     : Set Timestamp Prescale
ITMSWOEna         : TS counter uses Processor Clock, or clock from TPIU Interface
ITMTXEna          : Control if DWT packets are forwarded to the ITM
ITMSYNCEna        : Control if sync packets are transmitted
ITMTSEna          : Enable local timestamp generation
ITMEna            : Master Enable for ITM
ITMTER            : Set Trace Enable Register bitmap for 32*<Block>
ITMTPR            : Enable block 8*bit access from unprivledged code

Configure ETM
-------------
describeETM       : Provide information about the ETM implementation on this target

end
# ====================================================================
# ====================================================================
# ====================================================================


# Definitions for the CPU types we currently support
set $CPU_IMXRT102X=1
set $CPU_STM32=2
set $CPU_IMXRT106X=1
set $CPU_NRF=3
set $CPU_EFR32=4
set $CPU_TM4C=5

# ====================================================================
set $CDBBASE=0xE000EDF0
set $DWTBASE=0xE0001000
set $ITMBASE=0xE0000000
set $TPIUBASE=0xE0040000
set $ETMBASE=0xE0041000

define _setAddressesSTM32
  # Locations in the memory map for interesting things on STM32
  set $CPU = $CPU_STM32
  if (*0x5C001000)
    # DBGMCU->IDCODE is valid on the STM32H7
    set $RCCGPIO = 0x580244E0
    set $GPIOBASE = 0x58020000

    set $SWOBASE = 0x5C003000
    set $SWTFBASE = 0x5C004000
    set $CSTFBASE = 0x5C013000
    set $ETFBASE = 0x5C014000
    set $TPIUBASE = 0x5C015000
  else
    set $RCCGPIO = 0x40023830
    set $GPIOBASE = 0x40020000
  end
end

define _setAddressesIMXRT
# Locations in the memory map for interesting things on IMXRT
end

define _setAddressesNRF
# Locations in the memory map for interesting things on NRF
end

define _setAddressesETM4
# Locations in the memory map for ETMv4 registers

set $ETM4BASE=0xE0041000
# Programming Control Register
set $TRCPRGCTLR=$ETM4BASE+0x004
# Select Control Register
set $TRCPROCSELR=$ETM4BASE+0x008
# Trace Status Register
set $TRCSTATR=$ETM4BASE+0x00C
# Trace Configuration Register
set $TRCCONFIGR=$ETM4BASE+0x010
# Auxiliary Control Register
set $TRCAUXCTLR=$ETM4BASE+0x018
# Event Control 0 Register
set $TRCEVENTCTL0R=$ETM4BASE+0x020
# Event Control 1 Register
set $TRCEVENTCTL1R=$ETM4BASE+0x024
# Stall Control Register
set $TRCSTALLCTLR=$ETM4BASE+0x02C
# Global Timestamp Control Register
set $TRCTSCTLR=$ETM4BASE+0x030
# Synchronization Period Register
set $TRCSYNCPR=$ETM4BASE+0x034
# Cycle Count Control Register
set $TRCCCCTLR=$ETM4BASE+0x038
# Branch Broadcast Control Register
set $TRCBBCTLR=$ETM4BASE+0x03c
# Trace ID Register
set $TRCTRACEIDR=$ETM4BASE+0x040
# Q Element Control Register
set $TRCQCTLR=$ETM4BASE+0x044
# ViewInst Main Control Register
set $TRCVICTLR=$ETM4BASE+0x080
# ViewInst Include/Exclude Control Register
set $TRCVIIECTLR=$ETM4BASE+0x084
# ViewInst Start/Stop Control Register
set $TRCVISSCTLR=$ETM4BASE+0x088
# ViewInst Start/Stop PE Comparator Control Register
set $TRCVIPCSSCTLR=$ETM4BASE+0x08c
# ViewData Main Control Register
set $TRCVDCTLR=$ETM4BASE+0x0a0
# ViewData Include/Exclude Single Address Comparator Control Register
set $TRCVDSACCTLR=$ETM4BASE+0x0a4
# ViewData Include/Exclude Address Range Compa
set $TRCVDARCCTLR=$ETM4BASE+0x0a8
# Device architecture register
set $TRCDEVARCH=$ETM4BASE+0xFBC
# Trace IDR base address
set $TRCIDR0=$ETM4BASE+0x1E0
end
# Trace Address comparator Value registers
set $TRCACVR0=$ETMBASE+0x400
set $TRCACVR1=$ETMBASE+0x400+8*1
set $TRCACATR0=$ETMBASE+0x480
set $TRCACATR1=$ETMBASE+0x480+8*1

define _setAddressesNRF52
  _setAddressesNRF
  set $NRF_P0_PIN_CNF=0x50000700
  set $NRF_CLOCK=0x40000000
end

define _setAddressesNRF53
  _setAddressesNRF
  set $CTIBASE=0xE0042000
  set $SCSBASE=0xE000E000
  set $BPUBASE=0xE0002000
  set $NRF_TAD_S=0xE0080000
  set $NRF_P0_S=0x50842500
  set $NRF_SPU_S=0x50003000
end

define _setAddressesEFR32MG12
# Locations in the memory map for interesting things on EFR32
end

define _setAddressesTM4C
  set $PORTF_BASE=0x40025000
  set $GPIODIR=0x400
  set $GPIOAFSEL=0x420
  set $GPIODR2R=0x500
  set $GPIODR4R=0x504
  set $GPIODR8R=0x508
  set $GPIODEN=0x51C
  set $GPIOLOCK=0x520
  set $GPIOCR=0x524
  set $GPIOPCTL=0x52C

  set $GPIOUNLOCKKEY=0x4C4F434B
end

# ====================================================================
define _startETMv4
  # Enable the return stack, global timestamping, Context ID, and Virtual context identifier tracing.
  set *($TRCCONFIGR) = 0x000018C1

  # Disable all event tracing.
  set *($TRCEVENTCTL0R) = 0
  set *($TRCEVENTCTL1R) = 0

  # Disable or enable stalling for instructions, if implemented
  if ($stall!=0)
    set *($TRCSTALLCTLR) = 0
  else
    set *($TRCSTALLCTLR) = (1<<13)|(1<<8)|(0x0f<<0)
  end

  # Trace sync every 4096 bytes of trace
  set *($TRCSYNCPR) = 0x0c

  # Do we want branch broadcasting?
  set *$TRCACVR0=0
  set *$TRCACVR1=0xFFFFFFFF
  set *$TRCACATR0=0
  set *$TRCACATR1=0
  set *($TRCCONFIGR) |= ($br_out<<3)
  set *($TRCBBCTLR) = ($br_out<<8)|0x03

  # Trace on ID 2
  set *($TRCTRACEIDR) = 2

  # Disable timestamp event
  set *($TRCTSCTLR) = 0

  # Enable ViewInst to trace everything
  set *($TRCVICTLR) = 0x201

  # No address range filtering for ViewInst
  set *($TRCVIIECTLR) = 0

  # No start or stop points for ViewInst
  set *($TRCVISSCTLR) = 0

  # ...and start
  set *($TRCPRGCTLR) |= (1<<0)

  while (((*$TRCSTATR)&(1<<0))==1)
  echo Wait for trace not idle\n
  end
end
# ====================================================================
define _startETMv4_modified
  echo ETMv4 Tracing is enabled\n
  # Enable the return stack, global timestamping, Context ID, and Virtual context identifier tracing.
  # Disabled global timestamp to not interfere with cycle count
  set *($TRCCONFIGR) = 0x000010C1

  # Disable all event tracing.
  set *($TRCEVENTCTL0R) = 0
  set *($TRCEVENTCTL1R) = 0

  # Disable or enable stalling for instructions, if implemented
  set *($TRCSTALLCTLR) = (1<<13)|(1<<8)|(0x0f<<0)

  # Trace sync every 256 bytes of trace
  set *($TRCSYNCPR) = 0x0c

  # Do we want branch broadcasting?
  set *$TRCACVR0=0
  set *$TRCACVR1=0xFFFFFFFF
  set *$TRCACATR0=0
  set *$TRCACATR1=0
  set *($TRCCONFIGR) |= ($br_out<<3)
  set *($TRCBBCTLR) = ($br_out<<8)|0x03

  # enable cycle count
  set *($TRCCONFIGR) |= 0x10
  set *($TRCCCCTLR) |= 0x0a

  # Trace on ID 2
  set *($TRCTRACEIDR) = 2

  # Disable timestamp event (This does not do anything)
  set *($TRCTSCTLR) = 0

  # Enable ViewInst to trace everything
  set *($TRCVICTLR) = 0x201

  # No address range filtering for ViewInst
  set *($TRCVIIECTLR) = 0

  # No start or stop points for ViewInst
  set *($TRCVISSCTLR) = 0

  # ...and start
  set *($TRCPRGCTLR) |= (1<<0)

  while (((*$TRCSTATR)&(1<<0))==1)
  echo Wait for trace not idle\n
  end
end
# ====================================================================
define _startETMv35

  # Allow access to device
  set *($ETMBASE+0xfb0) = 0xc5acce55

  # Enter configuration mode (write twice to be sure we reached it)
  set *($ETMBASE) = (1<<10)
  set *($ETMBASE) = (1<<10)

  # Set busID 2
  set *($ETMBASE+0x200) = 2

  # Set trigger event
  set *($ETMBASE+8) = 0x406f

  # Set to always enable in ETM Trace Enable Event
  set *($ETMBASE+0x20) = 0x6f

  # Trace and stall always enabled
  set *($ETMBASE+0x24) = 0x020000001

  # Stall when < 8 byes free in fifo
  set *($ETMBASE+0x2c) = 8

  # Enable trace
  set *($ETMBASE) = 0x0800 | ($stall << 7) | ($br_out << 8)

  # Essential that this bit is only cleared after everything else is done
  set *($ETMBASE) &= ~(1<<10)

end
# ====================================================================

define stopETM
  if (((*$TRCDEVARCH)&0xfff0ffff)  ==0x47704a13)
    set *($TRCPRGCTLR) &= ~(1<<0)
    while ((*$TRCSTATR)&(1<<0)==0)
      echo Wait for idle\n
    end
  else
    set *($ETMBASE) |= 0x400
  end
end
document stopETM
stopETM
end

# ====================================================================

define startETM
  #set language c

  set $br_out=0
  if $argc >= 1
    set $br_out=$arg0
  end

  _setAddressesETM4
  stopETM

  set $br_out=0
  if $argc >= 1
    set $br_out=$arg0
  end

  set $stall = 0
  if $argc >= 2
    set $stall = $arg1
  end


  if (((*$TRCDEVARCH)&0xfff0ffff)  ==0x47704a13)
    echo ETMv4 version active \n
    _startETMv4_modified
  else
    echo ETMv3 version active \n
    _startETMv35
  end

  #set language auto

end

document startETM
startETM <br_out> <stall>

Start ETMv3.5 or v4 macrocell

<br_out>     : 1 = Explicitly report branch events
<stall>      : 1 = Stall the CPU when trace buffer is full
end

# ====================================================================
define describeETM

  #set language c

  if (((*$TRCDEVARCH)&0xfff0ffff)  ==0x47704a13)
    echo ETMv4.
    output (((*$TRCDEVARCH)>>16)&0x0f)
    echo \n
    set $i=0
    while $i<8
      output $i
      echo :
      output/x *($TRCIDR0+4*$i)
      set $i = $i+1
      echo \n
    end

    if (((*$TRCIDR0)>>1)&3==3)
      echo Tracing of Load and Store instructions as P0 elements is supported\n
    else
      echo Tracing of Load and Store instructions as P0 elements is not supported\n
    end

    if (((*$TRCIDR0)>>3)&3==3)
      echo Data tracing is supported\n
    else
      echo Data tracing is not supported\n
    end

    if (((*$TRCIDR0)>>5)&1==1)
      echo Branch broadcast is supported\n
    else
      echo Branch broadcast is not supported\n
    end

    if (((*$TRCIDR0)>>6)&1==1)
      echo Conditional Tracing is supported\n
    else
      echo Conditional Tracing is not supported\n
    end

    if (((*$TRCIDR0)>>7)&1==1)
      echo Instruction Cycle Counting is supported\n
    else
      echo Instruction Cycle Counting is not supported\n
    end

    if (((*$TRCIDR0)>>9)&1==1)
      echo Return Stacking is supported\n
    else
      echo Return Stacking is not supported\n
    end

    if (((*($TRCIDR0+12))>>26)&3==3)
      echo Stall is supported\n
    else
      echo Stalling is not supported\n
    end

  else
    set $etmval = *($ETMBASE+0x1e4)
    output ((($etmval>>8)&0x0f)+1)
    echo .
    output (($etmval>>4)&0x0f)
    echo Rev
    output (($etmval)&0x0f)
    echo \n

    if (((($etmval)>>24)&0xff)==0x41)
      echo Implementer is ARM\n
    end
    if (((($etmval)>>24)&0xff)==0x44)
      echo Implementer is DEC\n
    end
    if (((($etmval)>>24)&0xff)==0x4D)
      echo Implementer is Motorola/Freescale/NXP\n
    end
    if (((($etmval)>>24)&0xff)==0x51)
      echo Implementer is Qualcomm\n
    end
    if (((($etmval)>>24)&0xff)==0x56)
      echo Implementer is Marvell\n
    end
    if (((($etmval)>>24)&0xff)==0x69)
      echo Implementer is Intel\n
    end

    if ($etmval&(1<<18))
      echo 32-bit Thumb instruction is traced as single instruction\n
    else
      echo 32-bit Thumb instruction is traced as two instructions\n
    end

    if ($etmval&(1<<19))
      echo Implements ARM architecture security extensions\n
    else
      echo No ARM architecture security extensions\n
    end

    if ($etmval&(1<<20))
      echo Uses alternative Branch Packet Encoding\n
    else
      echo Uses original Branch Packet Encoding\n
    end
  end

  #set language auto

end

document describeETM
Provide information about the ETM implementation on this target.
end

# ====================================================================

define prepareSWO
  #set language c

  set $clockspeed=72000000
  set $speed=2250000
  set $useTPIU=0
  set $useMan=0

  if $argc >= 1
    set $clockspeed = $arg0
  end

  if $argc >= 2
    set $speed = $arg1
  end

  if $argc >= 3
    set $useTPIU = $arg2
  end

  if $argc >= 4
    set $useMan = $arg3
  end

  # Make sure we can get to everything
  set *($ITMBASE+0xfb0) = 0xc5acce55
  set *($ETMBASE+0xfb0) = 0xc5acce55

  set *($CDBBASE+0xC)|=(1<<24)

  if ($useMan==0)
    # Use Async mode pin protocol (TPIU_SPPR)
    set *($TPIUBASE+0xF0) = 2
  else
    # Use Manchester mode pin protocol (TPIU_SPPR)
    set *($TPIUBASE+0xF0) = 1

    # There are two edges in a bit, so double the clock
    set $speed = $speed*2
  end

  # Output bits at speed dependent on system clock
  set *($TPIUBASE+0x10) = ((($clockspeed+$speed-1)/$speed)-1)

  if ($useTPIU==1)
    # Use TPIU formatter and flush
    set *($TPIUBASE+0x304) = 0x102
  else
    set *($TPIUBASE+0x304) = 0x100
  end

  # Flush all initial configuration
  set *($CDBBASE+0xC)|=(1<<24)
  set *($DWTBASE) = 0
  set *($ITMBASE+0xe80) = 0

  #set language auto
end
document prepareSWO
prepareSWO <ClockSpd> <Speed> <UseTPIU> <UseMan>: Prepare output trace data port at specified speed
  <ClockSpd>: Speed of the CPU SystemCoreClock
  <Speed>   : Speed to use (Ideally an integer divisor of SystemCoreClock)
  <UseTPIU> : Set to 1 to use TPIU
  <UseMan>  : Set to 1 use use Manchester encoding
end

# ====================================================================
define enableIMXRT102XSWO
  #set language c

  _setAddressesIMXRT
  # Store the CPU we are using
  set $CPU=$CPU_IMXRT102X

  # Set AD_B0_04 to be an input, and no drive (defaults to JTAG otherwise)
  set *0x401f80cc=5
  set *0x401f8240=0

  # Set AD_B0_11 to be SWO, with specific output characteristics
  set *0x401F80E8=6
  set *0x401F825C=0x6020

  #set language auto
end
document enableIMXRT102XSWO
enableIMXRT102XSWO Configure output pin on IMXRT102X for SWO use.
end

define enableIMXRT1021SWO
  #set language c

       enableIMXRT102XSWO
  #set language auto
end
# ====================================================================
define enableIMXRT101XTRACE
  set language c

  set $drive=4
  set $bits=4

  if $argc >= 1
    set $bits = $arg0
  end
    if (($bits<1) || ($bits==3) || ($bits>4))
    help enableSTM32TRACE
  end

  if $argc >= 2
    set $drive = $arg1
  end

  if ($drive > 7)
    help enableIMXRT101XTRACE
  end

  set $bits = $bits-1

  set $CPU=$CPU_IMXRT101X
  _setAddressesIMXRT

  # Ensure IOMUX clocks are on
  set *0x400FC078 |= 3<<2

  # =========== SORT OUT PINS FOR TRACE ============================

  # Do not set drive strength to 2 or 3 here...it causes crashes. No idea why
  # Mostly works  set $padval = ( 0<<0 ) | (1<<12) | (0<<14) | (1<<13) | (2<<6) | ($drive<<3)
  set $padval =               ( 1<<0 ) | (1<<12) | (0<<14) | (1<<13) | (2<<6) | ($drive<<3)

  # TRACECLK ALT7 on GPIO_AD_02
  # TRACEDATA0 ALT7 on GPIO_AD_00
  set *0x401f8040 = 7
  set *0x401f8048 = 7
  set *0x401f80f0 = $padval
  set *0x401f80f8 = $padval

  if ($bits>0)
    # TRACEDATA1 on GPIO_13
    set *0x401f8088 = 7
    set *0x401f8138 = $padval
  end

  if ($bits>1)
    # TRACEDATA2 on GPIO_12
    set *0x401f808c = 7
    set *0x401f813c = $padval
    # TRACEDATA3 on GPIO_11
    set *0x401f8090 = 7
    set *0x401f8140 = $padval
  end
  # =========== END IF SORTING OUT PINS FOR TRACE ==================

  # =========== SORT OUT CLOCK FOR TRACE =================
  # Turn off clock while setting up PODF (CCGR0 CG11)
  set *0x400fc068 = ((*0x400fc068) & ~(3<<22))

  # With clock gated we can safely update CSCDR1 TRACE_PODF for /4
  set *0x400fc024 = ((*0x400fc024) & ~(0xf<<25)) | (14<<25)
  # ...and set source to PLL2 (can also be PLL2PFD2 PLL2PFD0 or PLL2PFD1)
  set *0x400fc018 = ((*0x400fc018) & ~(3<<14)) | (0<<14)

  # Clock back on (CCGR0 CG11)
  set *0x400fc068 |= (3<<22)
  # =========== END OF SORTING OUT CLOCK FOR TRACE =================

  #Enable DEMCR
  set *(0xE000EDFC)|=(1<<24)

  # Set port size (TPIU_CSPSR)
  set *($TPIUBASE+4) = (1<<$bits)

  # Set TPIU_SPPR to parallel trace port mode
  set *($TPIUBASE+0xf0) = 0

  set *($TPIUBASE+0x304) = 0x102
  set language auto
end

document enableIMXRT101XTRACE
enableIMXRT102XTRACE <Width> <Drive>: Enable TRACE on IMXRT1010 pins
  <Width>   : Number of bits wide (1,2 or 4 only)
  <Drive>   : Drive strength (0=lowest, 7=highest)
end
# ====================================================================
define enableIMXRT102XTRACE
  set language c

  set $drive=1
  set $bits=1

  set $CPU=$CPU_IMXRT102X
  _setAddressesIMXRT

  set *0x400FC078 |= 3<<2

  # =========== SORT OUT PINS FOR TRACE ============================

  # TRACECLK ALT6 on GPIO_AD_B0_10
  # TRACEDATA0 ALT6 on GPIO_AD_B0_12
  set *0x401f80ec = 6
  set *0x401f80e4 = 6

  # Do not set drive strength to 2 or 3 here...it causes crashes. No idea why
# Mostly works  set $padval = ( 0<<0 ) | (1<<12) | (0<<14) | (1<<13) | (2<<6) | (4<<3)
  set $padval =               ( 0<<0 ) | (0<<12) | (0<<14) | (1<<13) | (3<<6) | (2<<3)
#set $padval = 0x10b0
  set *0x401f8258 = $padval
  set *0x401f8260 = $padval
  # =========== END IF SORTING OUT PINS FOR TRACE ==================


  # =========== SORT OUT CLOCK FOR TRACE =================
  # Turn off clock while setting up PODF (CCGR0 CG11)
  set *0x400fc068 = ((*0x400fc068) & ~(3<<22))

  # With clock gated we can safely update CSCDR1 TRACE_PODF for /4
  set *0x400fc024 = ((*0x400fc024) & ~(3<<25)) | (3<<25)
  # ...and set source to PLL2 (can also be PLL2PFD2 PLL2PFD0 or PLL2PFD1)
  set *0x400fc018 = ((*0x400fc018) & ~(3<<14)) | (1<<14)

  # Clock back on (CCGR0 CG11)
  set *0x400fc068 |= (3<<22)
  # =========== END OF SORTING OUT CLOCK FOR TRACE =================

  #Enable DEMCR
  set *(0xE000EDFC)|=(1<<24)

  # Set port size (TPIU_CSPSR)
  set *($TPIUBASE+4) = (1<<($bits-1))

  # Set TPIU_SPPR to parallel trace port mode
  set *($TPIUBASE+0xf0) = 0

  set *($TPIUBASE+0x304) = 0x102
  set language auto
end
document enableIMXRT102XTRACE
enableIMXRT102XTRACE : Enable TRACE on IMXRT1020 pins (only 1-bit is supported by the chip)
end
# ====================================================================
define enableIMXRT106XSWO
  #set language c

  _setAddressesIMXRT
  # Store the CPU we are using
  set $CPU=$CPU_IMXRT106X

  # Disable Trace Clocks while we change them (CCM_CCGR0)
  set *0x400FC068&=~(3<<22)
  set *0x400FC068|=(3<<22)

  # Set Trace clock input to be from PLL2 PFD2 (CBCMR1, 396 MHz)
  set *0x400Fc018&=~(3<<14)
  set *0x400Fc018|=(1<<14)

  # Set divider to be 3 (CSCDR1, 132 MHz)
  set *0x400Fc024&=~(3<<25)
  set *0x400Fc024|=(2<<25)

  # Enable Trace Clocks (CCGR0)
  set *0x400FC068|=(3<<22)

  # Set AD_B0_10 to be SWO, with specific output characteristics (MUX_CTL & PAD_CTL)
  set *0x401F80E4=9
  set *0x401F82D4=0xB0A1

  #set language auto
end
document enableIMXRT106XSWO
enableIMXRT1021SWO Configure output pin on IMXRT1060 for SWO use.
end
# ====================================================================

define enableSTM32SWO
  #set language c

  set $tgt=1
  if $argc >= 1
    set $tgt = $arg0
  end

  set $CPU=$CPU_STM32
   _setAddressesSTM32
  if (($tgt==4) || ($tgt==7))
    # STM32F4/7 variant: SWO on PB3.
    enableSTM32Pin 1 3 3
  else
    # STM32F1 variant.
    # RCC->APB2ENR |= RCC_APB2ENR_AFIOEN;
    set *0x40021018 |= 1
    # AFIO->MAPR |= (2 << 24); // Disable JTAG to release TRACESWO
    set *0x40010004 |= 0x2000000
  end
  # Common initialisation.
  # DBGMCU->CR |= DBGMCU_CR_TRACE_IOEN;
  set *0xE0042004 |= 0x20

  #set language auto
end
document enableSTM32SWO
enableSTM32SWO Configure output pin on STM32 for SWO use.
end
# ====================================================================
define enableSAMD5XSWD
  #set language c

  # Enable peripheral channel clock on GCLK#0
  # GCLK->PHCTRL[47] = GCLK_PCHCTRL_GEN(0)
  set *(unsigned char *)0x40001D3C = 0
  # GCLK->PHCTRL[47] |= GCLK_PCHCTRL_CHEN
  set *(unsigned char *)0x40001D3C |= 0x40
  # Configure PINMUX for GPIOB.30. '7' is SWO.
  set *(unsigned char *)0x410080BF |= 0x07
  set *(unsigned char *)0x410080DE = 0x01

  #set language auto
end
document enableSAMD5XSWD
enableSAMD5XSWD Configure output pin on SAM5X for SWO use.
end

# ====================================================================
define enableEFR32MG12SWO
  #set language c


  _setAddressesEFR32MG12
  # Store the CPU we are using
  set $CPU=$CPU_EFR32

  # Enable the GPIO clock (HFBUSCLKEN0)
  # CMU->HFBUSCLKEN0 |= CMU_HFBUSCLKEN0_GPIO
  set *0x400E40B0 |= (1<<3)

  # Enable Trace Clocks (CMU_OSCENCMD_AUXHFRCOEN)
  # CMU->OSCENCMD = CMU_OSCENCMD_AUXHFRCOEN
  set *0x400E4060 = (1<<4)

  # Enable SWO Output
  # GPIO->ROUTEPEN |= GPIO_ROUTEPEN_SWVPEN
  set *0x4000A440 |= (1<<4)

  # Route SWO to correct pin (GPIO->ROUTELOC0=0/_GPIO_ROUTELOC0_SWVLOC_MASK=3/BSP_TRACE_SWO_LOCATION=0)
  # GPIO->ROUTELOC0 = (GPIO->ROUTELOC0 & ~(_GPIO_ROUTELOC0_SWVLOC_MASK)) | BSP_TRACE_SWO_LOCATION
  set *0x4000A444 = 0

  # Configure GPIO Port F, Pin 2 for output
  # GPIO->P[5].MODEL &= ~(_GPIO_P_MODEL_MODE2_MASK);
  # GPIO->P[5].MODEL |= GPIO_P_MODEL_MODE2_PUSHPULL;
  set *0x4000A0F4 &= ~(0xF00)
  set *0x4000A0F4 |= (4 << 8)

  #set language auto
end
document enableEFR32MG12SWO
enableEFR32MG12SWO Configure output pin on EFR32MG12 for SWO use.
end


# ====================================================================
# Enable CORTEX TRACE on preconfigured pins
define _doTRACE
  # Must be called with $bits containing number of bits to set trace for

  set *($ITMBASE+0xfb0) = 0xc5acce55
  set *($ETMBASE+0xfb0) = 0xc5acce55
  set *($TPIUBASE+0xfb0) = 0xc5acce55

  # Set port size (TPIU_CSPSR)
  set *($TPIUBASE+4) = (1<<$bits)

  # Set pin protocol to Sync Trace Port (TPIU_SPPR)
  set *($TPIUBASE+0xF0)=0

  set *($TPIUBASE+0x304) = 0x102
end
# ====================================================================
define enableSTM32Pin
  #set language c
  set $_GPIOPORT = $GPIOBASE + 0x400 * $arg0

  # Enable GPIO port in RCC
  set *($RCCGPIO) |= (0x1<<$arg0)

  # MODER: Alternate Function
  set *($_GPIOPORT+0x00) &= ~(0x3<<2*$arg1)
  set *($_GPIOPORT+0x00) |=   0x2<<2*$arg1

  # OTYPER: Push-Pull
  set *($_GPIOPORT+0x04) &= ~(0x1<<$arg1)

  # OSPEEDR: Drive speed
  set *($_GPIOPORT+0x08) &= ~(0x3<<2*$arg1)
  set *($_GPIOPORT+0x08) |= $arg2<<2*$arg1

  # PUPDR: No pullup or pulldown
  set *($_GPIOPORT+0x0C) &= ~(0x3<<2*$arg1)

  # AFRL: AF0
  if ($arg1 < 8)
    set *($_GPIOPORT+0x20) &= ~(0xF<<4*$arg1)
  else
    set *($_GPIOPORT+0x24) &= ~(0xF<<4*($arg1 - 8))
  end

  # LOCKR: lock pin until the next reset
  set *($_GPIOPORT+0x1C) = 0x10000 | (0x1<<$arg1)
  set *($_GPIOPORT+0x1C) = 0x00000 | (0x1<<$arg1)
  set *($_GPIOPORT+0x1C) = 0x10000 | (0x1<<$arg1)
  set $_null = *($_GPIOPORT+0x1C)

  #set language auto
end
document enableSTM32Pin
enableSTM32Pin <Port> <Pin> <Drive>: Enable TRACE function AF0 on a single STM32 pin
  <Port>    : Number of the port (0=A, 1=B, 2=C, 3=D, 4=E, 5=F, 6=G, ...)
  <Pin>     : Pin number in [0, 15]
  <Drive>   : Drive strength (0=lowest, 3=highest)
end

# ====================================================================
define enableSTM32TRACE
  #set language c

  set $bits=4
  set $drive=1
  set $remap=0

  if $argc >= 1
    set $bits = $arg0
  end
    if (($bits<1) || ($bits==3) || ($bits>4))
    help enableSTM32TRACE
  end

  if $argc >= 2
    set $drive = $arg1
  end

  if ($drive > 3)
    help enableSTM32TRACE
  end

  if $argc >= 3
    set $remap = $arg2
  end

  set $bits = $bits-1
  set $CPU=$CPU_STM32

  _setAddressesSTM32

  # Enable Trace TRCENA (DCB DEMCR) needed for clocks
  set *($CDBBASE+0xC)=(1<<24)

  # Enable compensation cell
  set *0x40023844 |= (1<<14)
  set *0x40013820 |=1

  # Setup PE2 & PE3
  enableSTM32Pin 4 2 $drive
  enableSTM32Pin 4 3 $drive

  if ($bits>0)
     # Setup PE4
     enableSTM32Pin 4 4 $drive
  end

  if ($bits>1)
    # Setup PE5 & PC12 
    enableSTM32Pin 4 5 $drive
    enableSTM32Pin 4 6 $drive
    if ($remap)
      enableSTM32Pin 2 12 $drive 
    else
      enableSTM32Pin 4 6 $drive
    end
  end

  # Set number of bits in DBGMCU_CR
  set *0xE0042004 &= ~(3<<6)

  if ($bits<3)
     set *0xE0042004 |= ((($bits+1)<<6) | (1<<5))
  else
     set *0xE0042004 |= ((3<<6) | (1<<5))
  end

  # Enable Trace TRCENA (DCB DEMCR)
  set *($CDBBASE+0xC)=(1<<24)

  # Finally start the trace output
  _doTRACE

  #set language auto
end
document enableSTM32TRACE
enableSTM32TRACE <Width>: Enable TRACE on STM32 pins
  <Width>   : Number of bits wide (1,2 or 4 only)
  <Drive>   : Drive strength (0=lowest, 3=highest)
end
# ====================================================================
define enableNRF52TRACE
  #set language c

  set $bits=4
  set $cspeed=1
  set $drive=3

  if $argc >= 1
    set $bits = $arg0
  end
    if (($bits<1) || ($bits==3) || ($bits>4))
    help enableNRF53TRACE
  end

  if $argc >= 2
    set $drive=$arg1
  end
  if (($drive!=0) & ($drive!=3))
     help enableNRF52TRACE
  end

  if $argc >= 3
    set $cspeed=$arg2
  end
  if (( $cspeed < 0 ) || ( $cspeed > 3))
    help enableNRF52TRACE
  end

  set $bits = $bits-1
  set $CPU=$CPU_NRF

  _setAddressesNRF52

  # from modules/nrfx/mdk/system_nrf52.c
  # CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  set *($CDBBASE+0xC) |= (1<<24)

  # NRF_CLOCK->TRACECONFIG |= CLOCK_TRACECONFIG_TRACEMUX_Parallel << CLOCK_TRACECONFIG_TRACEMUX_Pos;
  set *($NRF_CLOCK+0x0000055C) &= ~(3 << 16)
  set *($NRF_CLOCK+0x0000055C) |= (2 << 16)
  set *($NRF_CLOCK+0x0000055C) &= ~(3 << 0)
  set *($NRF_CLOCK+0x0000055C) |= ($cspeed << 0)

  if ($bits>0)
    # NRF_P0->PIN_CNF[18] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) | (GPIO_PIN_CNF_INPUT_Connect << GPIO_PIN_CNF_INPUT_Pos) | (GPIO_PIN_CNF_DIR_Output << GPIO_PIN_CNF_DIR_Pos);
    set *($NRF_P0_PIN_CNF+18*4) = (($drive<<8) | (0<<1) | (1<<0))
    # NRF_P0->PIN_CNF[20] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) | (GPIO_PIN_CNF_INPUT_Connect << GPIO_PIN_CNF_INPUT_Pos) | (GPIO_PIN_CNF_DIR_Output << GPIO_PIN_CNF_DIR_Pos);
    set *($NRF_P0_PIN_CNF+20*4) = (($drive<<8) | (0<<1) | (1<<0))
    if ($bits>1)
      # NRF_P0->PIN_CNF[14] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) | (GPIO_PIN_CNF_INPUT_Connect << GPIO_PIN_CNF_INPUT_Pos) | (GPIO_PIN_CNF_DIR_Output << GPIO_PIN_CNF_DIR_Pos);
      set *($NRF_P0_PIN_CNF+14*4) = (($drive<<8) | (0<<1) | (1<<0))
      # NRF_P0->PIN_CNF[15] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) | (GPIO_PIN_CNF_INPUT_Connect << GPIO_PIN_CNF_INPUT_Pos) | (GPIO_PIN_CNF_DIR_Output << GPIO_PIN_CNF_DIR_Pos);
      set *($NRF_P0_PIN_CNF+15*4) = (($drive<<8) | (0<<1) | (1<<0))
      # NRF_P0->PIN_CNF[16] = (GPIO_PIN_CNF_DRIVE_H0H1 << GPIO_PIN_CNF_DRIVE_Pos) | (GPIO_PIN_CNF_INPUT_Connect << GPIO_PIN_CNF_INPUT_Pos) | (GPIO_PIN_CNF_DIR_Output << GPIO_PIN_CNF_DIR_Pos);
      set *($NRF_P0_PIN_CNF+16*4) = (($drive<<8) | (0<<1) | (1<<0))
    end
  end
  # Finally start the trace output
  _doTRACE

  #set language auto
end
document enableNRF52TRACE
enableNRF52TRACE <Drive> <Speed> : Enable TRACE on NRF52 pins (not nrf52833 or nrf52840)
  <Width>   : Number of bits wide (1,2 or 4 only)
  <Drive>   : Drive strength (0 (low), 3 (high))
  <Speed>   : Clock Speed (0..3, 0 fastest)
end
# ====================================================================
define enableNRF53TRACE
  #set language c

  set $bits=4
  set $cspeed=1
  set $drive=11
  #11

  if $argc >= 1
    set $bits = $arg0
  end
    if (($bits<1) || ($bits==3) || ($bits>4))
    help enableNRF53TRACE
  end

  if $argc >= 2
    set $drive=$arg1
  end

  if ((($drive<0) || ($drive>3)) && ($drive!=11))
     help enableNRF53TRACE
  end

  if $argc >= 3
    set $cspeed=$arg2
  end
  if (( $cspeed < 0 ) || ( $cspeed > 3))
    help enableNRF53TRACE
  end

  set $bits = $bits-1
  set $CPU=$CPU_NRF

  _setAddressesNRF53
  # Actions from Section 8.9 of the manual
  # NRF_TAD_S->ENABLE = TAD_ENABLE_ENABLE_Msk
  set *($NRF_TAD_S+0x500) = 1

  # NRF_TAD_S->CLOCKSTART = TAD_CLOCKSTART_START_Msk
  set *($NRF_TAD_S+4) = 1

  # Release permissions ( NRF_SPU_S->GPIOPORT[0].PERM )
  # Set pins to be controlled
  # NRF_TAD_S->PSEL.TRACECLK = TAD_PSEL_TRACECLK_PIN_Traceclk
  # NRF_TAD_S->PSEL.TRACEDATAX = TAD_PSEL_TRACEDATA0_PIN_TracedataX

  set *($NRF_SPU_S+0x4c0 ) &=~ ( (1<<12)|(1<<11) )

  set *($NRF_TAD_S+0x504+0) = 12
  set *($NRF_TAD_S+0x504+4) = 11
  set *($NRF_P0_S + 0x200 + 4*12  ) = (7<<28) | ( $drive << 8)
  set *($NRF_P0_S + 0x200 + 4*11  ) = (7<<28) | ( $drive << 8)

  if ($bits>0)
    set *($NRF_SPU_S+0x4c0 ) &=~ ( 1<<10 )

    set *($NRF_TAD_S+0x504+8) = 10
    set *($NRF_P0_S + 0x200 + 4*10  ) = (7<<28) | ( $drive << 8)

    if ($bits>1)
      set *($NRF_SPU_S+0x4c0 ) &=~ ( (1<<9)|(1<<8) )
      set *($NRF_TAD_S+0x504+0x0C) = 9
      set *($NRF_TAD_S+0x504+0x10) = 8
      set *($NRF_P0_S + 0x200 + 4*9  ) = (7<<28) | ( $drive << 8)
      set *($NRF_P0_S + 0x200 + 4*8  ) = (7<<28) | ( $drive << 8)
    end
  end


  # NRF_TAD_S->TRACEPORTSPEED = TAD_TRACEPORTSPEED_TRACEPORTSPEED_64MHz
  # Can be 0..3
  set *($NRF_TAD_S+0x518) = $cspeed

  # Enable Trace TRCENA (DCB DEMCR)
  set *($CDBBASE+0xC)=(1<<24)

  # Finally start the trace output
  _doTRACE

  #set language auto
end
document enableNRF53TRACE
enableNRF53TRACE <Width> <drive> <speed> : Enable TRACE on NRF pins
  <Width>   : Number of bits wide (1,2 or 4 only)
  <Drive>   : Drive strength (0 (lowest), 1, 2, 3 or 11 (highest))
  <Speed>   : Clock Speed (0..3, 0 fastest)
end
# ====================================================================
define enableTM4C123TRACE
  #set language c

  set $bits=2
  set $drive=2

  if $argc >= 1
    set $bits = $arg0
  end

  if (($bits<1) || ($bits==3) || ($bits>4))
    help enableTM4C123TRACE
  end

  if $argc >= 2
    set $drive = $arg1
  end

  if ($drive > 2)
    help enableTM4C123TRACE
  end

  set $bits = $bits-1
  set $CPU=$CPU_TM4C

  _setAddressesTM4C

  if ($drive == 0)
    set $DRIVEREG=$GPIODR2R
  end
  if ($drive == 1)
    set $DRIVEREG=$GPIODR4R
  end
  if ($drive == 2)
    set $DRIVEREG=$GPIODR8R
  end

  # Setup PF3 (tclk) and PF2 (td0)
  # Digital Enable, Direction, AF sel, drive strength, and mux
  set *($PORTF_BASE + $GPIODIR) |= 0b1100
  set *($PORTF_BASE + $GPIODEN) |= 0b1100
  set *($PORTF_BASE + $GPIOAFSEL) |= 0b1100
  set *($PORTF_BASE + $DRIVEREG) |= 0b1100
  set *($PORTF_BASE + $GPIOPCTL) |= 0xEE00


  if ($bits >= 1)
    # Setup PF1 (td1)
    set *($PORTF_BASE + $GPIODIR) |= 0b0010
    set *($PORTF_BASE + $GPIODEN) |= 0b0010
    set *($PORTF_BASE + $GPIOAFSEL) |= 0b0010
    set *($PORTF_BASE + $DRIVEREG) |= 0b0010
    set *($PORTF_BASE + $GPIOPCTL) |= 0x00E0
  end

  if ($bits > 2)
    # Unloxk PF0 so we can configure it as alt function TDR2 (14)
    set *($PORTF_BASE + $GPIOLOCK) = $GPIOUNLOCKKEY
    set *($PORTF_BASE + $GPIOCR) |= 1

    # Setup PF0 (td2) and PF4 (td3)
    set *($PORTF_BASE + $GPIODIR) |= 0b10001
    set *($PORTF_BASE + $GPIODEN) |= 0b10001
    set *($PORTF_BASE + $GPIOAFSEL) |= 0b10001
    set *($PORTF_BASE + $DRIVEREG) |= 0b10001
    set *($PORTF_BASE + $GPIOPCTL) |= 0xE000E
  end

  # Set number of bits in DBGMCU_CR
  set *0xE0042004 &= ~(3<<6)

  if ($bits<3)
     set *0xE0042004 |= ((($bits+1)<<6) | (1<<5))
  else
     set *0xE0042004 |= ((3<<6) | (1<<5))
  end

  # Enable Trace TRCENA (DCB DEMCR)
  set *($CDBBASE+0xC)=(1<<24)

  # Finally start the trace output
  _doTRACE

  #set language auto
end
document enableTM4C123TRACE
enableTM4C123TRACE <Width>: Enable TRACE on STM32 pins
  <Width>   : Number of bits wide (1,2 or 4 only (2 default))
  <Drive>   : Drive strength (0=lowest, 2=highest)
end
# ====================================================================
define dwtPOSTCNT
  #set language c

  if ($argc!=1)
    help dwtPOSTCNT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<22)
    else
      set *($DWTBASE) &= ~(1<<22)
    end
  end

  #set language auto
end
document dwtPOSTCNT
dwtPOSTCNT <0|1> Enable POSTCNT underflow event counter packet generation
end
# ====================================================================
define dwtFOLDEVT
  #set language c

  if ($argc!=1)
    help dwtFOLDEVT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<21)
    else
      set *($DWTBASE) &= ~(1<<21)
    end
  end

  #set language auto
end
document dwtFOLDEVT
dwtFOLDEVT <0|1> Enable folded-instruction counter overflow event packet generation
end
# ====================================================================
define dwtLSUEVT
  #set language c

  if ($argc!=1)
    help dwtLSUEVT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<20)
    else
      set *($DWTBASE) &= ~(1<<20)
    end
  end

  #set language auto
end
document dwtLSUEVT
dwtLSUEVT <0|1> Enable LSU counter overflow event packet generation
end
# ====================================================================
define dwtSLEEPEVT
  #set language c

  if ($argc!=1)
    help dwtSLEEPEVT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<19)
    else
      set *($DWTBASE) &= ~(1<<19)
    end
  end

  #set language auto
end
document dwtSLEEPEVT
dwtSLEEPEVT <0|1> Enable Sleep counter overflow event packet generation
end
# ====================================================================
define dwtDEVEVT
  #set language c

  if ($argc!=1)
    help dwtCEVEVT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<18)
    else
      set *($DWTBASE) &= ~(1<<18)
    end
  end

  #set language auto
end
document dwtDEVEVT
dwtDEVEVT <0|1> Enable Exception counter overflow event packet generation
end
# ====================================================================
define dwtCPIEVT
  #set language c

  if ($argc!=1)
    help dwtCPIEVT
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<17)
    else
      set *($DWTBASE) &= ~(1<<17)
    end
  end

  #set language auto
end
document dwtCPIEVT
dwtCPIEVT <0|1> Enable CPI counter overflow event packet generation
end
# ====================================================================
define dwtTraceException
  #set language c

  if ($argc!=1)
    help dwtTraceException
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<16)
    else
      set *($DWTBASE) &= ~(1<<16)
    end
  end

  #set language auto
end
document dwtTraceException
dwtTraceException <0|1> Enable Exception Trace Event packet generation
end
# ====================================================================
define dwtSamplePC
  #set language c

  if ($argc!=1)
    help dwtSamplePC
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<12)
    else
      set *($DWTBASE) &= ~(1<<12)
    end
  end

  #set language auto
end
document dwtSamplePC
dwtSamplePC <0|1> Enable PC sample using POSTCNT interval
end
# ====================================================================
define dwtSyncTap
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>3))
    help dwtSyncTap
  else
    set *($CDBBASE|0xC) |= 0x1000000
    set *($DWTBASE) &= ~(0x03<<10)
    set *($DWTBASE) |= (($arg0&0x03)<<10)
  end

  #set language auto
end
document dwtSyncTap
dwtSyncTap <0..3> Set how often Sync packets are sent out (None, CYCCNT[24], CYCCNT[26] or CYCCNT[28])
end
# ====================================================================
define dwtPostTap
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help dwtPostTap
  else
    set *($CDBBASE|0xC) |= 0x1000000
    if ($arg0==0)
      set *($DWTBASE) &= ~(1<<9)
    else
      set *($DWTBASE) |= (1<<9)
    end
  end

  #set language auto
end
document dwtPostTap
dwtPostTap <0..1> Sets the POSTCNT tap (CYCCNT[6] or CYCCNT[10])
end
# ====================================================================
define dwtPostInit
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>15))
    help dwtPostInit
  else
    set *($CDBBASE+0xC) |= 0x1000000
    set *($DWTBASE) &= ~(0x0f<<5)
    set *($DWTBASE) |= (($arg0&0x0f)<<5)
  end

  #set language auto
end
document dwtPostInit
dwtPostInit <0..15> Sets the initial value for the POSTCNT counter
end
# ====================================================================
define dwtPostReset
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>15))
    help dwtPostReset
  else
    set *($CDBBASE+0xC) |= 0x1000000
    set *($DWTBASE) &= ~(0x0f<<1)
    set *($DWTBASE) |= (($arg0&0x0f)<<1)
  end

  #set language auto
end
document dwtPostReset
dwtPostReset <0..15> Sets the reload value for the POSTCNT counter
In conjunction with the dwtPostTap, this gives you a relatively wide range
of sampling speeds.  Lower numbers are faster.
end
# ====================================================================
define dwtCycEna
  #set language c

  if ($argc!=1)
    help dwtCycEna
  else
    set *($CDBBASE+0xC) |= 0x1000000
    if ($arg0==1)
      set *($DWTBASE) |= (1<<0)
    else
      set *($DWTBASE) &= ~(1<<0)
    end
  end

  #set language auto
end
document dwtCycEna
dwtCycEna <0|1> Enable or disable CYCCNT
end
# ====================================================================
# ====================================================================
define ITMId
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>127))
    help ITMBusId
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    set *($ITMBASE+0xe80) &= ~(0x7F<<16)
    set *($ITMBASE+0xe80) |= (($arg0&0x7f)<<16)
  end

  #set language auto
end
document ITMId
ITMId <0..127>: Set the ITM ID for this device
end
# ====================================================================
define ITMGTSFreq
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>3))
    help ITMGTSFreq
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    set *($ITMBASE+0xe80) &= ~(0x3<<10)
    set *($ITMBASE+0xe80) |= (($arg0&3)<<10)
  end

  #set language auto
end
document ITMGTSFreq
ITMGTSFreq <0..3> Set Global Timestamp frequency
          [0-Disable, 1-Approx 128 Cycles,
           2-Approx 8192 Cycles, 3-Whenever possible]
end
# ====================================================================
define ITMTSPrescale
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>3))
    help ITMGTSFreq
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    set *($ITMBASE+0xe80) &= ~(0x3<<8)
    set *($ITMBASE+0xe80) |= (($arg0&3)<<8)
  end

  #set language auto
end
document ITMTSPrescale
ITMTSPrescale <0..3> Set Timestamp Prescale [0-No Prescale, 1-/4, 2-/16, 3-/64
end
# ====================================================================
define ITMSWOEna
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help ITMSWOEna
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    if ($arg0==0)
      set *($ITMBASE+0xe80) &= ~(0x1<<4)
    else
      set *($ITMBASE+0xe80) |= (($arg0&1)<<4)
    end
  end

  #set language auto
end
document ITMSWOEna
ITMSWOEna <0|1> 0-TS counter uses Processor Clock
                1-TS counter uses clock from TPIU Interface, and is held in reset while the output line is idle.
end
# ====================================================================
define ITMTXEna
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help ITMTXEna
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    if ($arg0==0)
      set *($ITMBASE+0xe80) &= ~(0x1<<3)
    else
      set *($ITMBASE+0xe80) |= (($arg0&1)<<3)
    end
  end

  #set language auto
end
document ITMTXEna
ITMTXEna <0|1> 0-DWT packets are not forwarded to the ITM
               1-DWT packets are output to the ITM
end
# ====================================================================
define ITMSYNCEna
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help ITMSYNCEna
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    if ($arg0==0)
      set *($ITMBASE+0xe80) &= ~(0x1<<2)
    else
      set *($ITMBASE+0xe80) |= (($arg0&1)<<2)
    end
  end

  #set language auto
end
document ITMSYNCEna
ITMSYNCEna <0|1> 0-Sync packets are not transmitted
                 1-Sync paclets are transmitted
end
# ====================================================================
define ITMTSEna
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help ITMTSEna
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    if ($arg0==0)
      set *($ITMBASE+0xe80) &= ~(0x1<<1)
    else
      set *($ITMBASE+0xe80) |= (($arg0&1)<<1)
    end
  end

  #set language auto
end
document ITMTSEna
ITMTSEna <0|1> Enable local timestamp generation
end
# ====================================================================
define ITMEna
  #set language c

  if (($argc!=1) || ($arg0<0) || ($arg0>1))
    help ITMEna
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    if ($arg0==0)
      set *($ITMBASE+0xe80) &= ~(0x1<<0)
    else
      set *($ITMBASE+0xe80) |= (($arg0&1)<<0)
    end
  end

  #set language auto
end
document ITMEna
ITMEna <0|1> Master Enable for ITM
end
# ====================================================================
define ITMTER
  #set language c

  if (($argc!=2) || ($arg0<0) || ($arg0>7))
    help ITMTER
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    set *($ITMBASE+0xe00+4*$arg0) = $arg1
  end

  #set language auto
end
document ITMTER
ITMTER <Block> <Bitmask> Set Trace Enable Register bitmap for 32*<Block>
end
# ====================================================================
define ITMTPR
  #set language c

  if ($argc!=1)
    help ITMTPR
  else
    set *($ITMBASE+0xfb0) = 0xc5acce55
    set *($ITMBASE+0xe40) = $arg0
  end

  #set language auto
end
document ITMTPR
ITMTPR <Bitmask> Enable block 8*bit access from unprivledged code
end
# ====================================================================
define tracetest
  set language c

  if ($argc!=1)
    help tracetest
  else
    set *($TPIUBASE+0xfb0) = 0xc5acce55
    if ($arg0 == 0)
      set *($TPIUBASE+0x204) = 0
    else
      set *($TPIUBASE+0x204) = (1<<17) | (1 << ($arg0&0xf))
    end
  end
  set language auto
end
document tracetest
tracetest <Mode> Switch TRACE output to specified test mode;
   0 - Normal operation
   1 - Walking 1's
   2 - Walking 0's
   3 - 0xAA / 0x55
   4 - 0xFF / 0x00
end
# ====================================================================
