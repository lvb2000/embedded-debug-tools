# import os

# os.system('rm -rf build')
# os.system('meson setup build')
# os.system('ninja -C build')

from build.orbethon import *
import argparse

arg2tsType = {
    "a" : TSType.TSAbsolute,
    "r" : TSType.TSRelative,
    "d" : TSType.TSDelta,
    "s" : TSType.TSStamp,
    "t" : TSType.TSStampDelta
}


def processOptions(args):
    """
    Takes the input arguments and creates a options struct which is needed as input for orbetto tool
    Input:
        - args : arguments received from argparse
    Return:
        - options struct
    """
    # init Options class
    options = Options_Struct()
    # set options based on args
    options.cps = args.cpufreq * 1000
    options.tsType = arg2tsType[args.timestamp]
    options.endTerminate = args.eof
    print(args.input_file)
    print(args.elf)
    options.file = args.input_file
    options.elfFile = args.elf
    return options



def init_argparse():
    """ 
    Initializes the argparse library with the needed arguments and the according defaults.
    Return:
        - all parsed arguments
    """
    parser = argparse.ArgumentParser(
        prog='Orbethon', description='Run Orbetto Tool from Python.')
    parser.add_argument('-T', '--timestamp',
                        help="Add absolute, relative (to session start),delta, system timestamp or system timestamp delta to output."
                        + "Note a,r & d are host dependent and you may need to run orbuculum with -H.",
                        type=str,
                        choices=['a', 'r', 'd', 's', 't'],
                        default='s'
                        )
    parser.add_argument('-C', '--cpufreq',
                        help="<Frequency in KHz> (Scaled) speed of the CPU."
                        + "generally /1, /4, /16 or /64 of the real CPU speed",
                        type=int,
                        default=216000
                        )
    parser.add_argument('-E', '--eof',
                        help="Terminate when the file/socket ends/is closed, or wait for more/reconnect",
                        action='store_true',
                        default=True
                        )
    parser.add_argument('-f', '--input_file',
                        help="<filename> Take input from specified file",
                        type=str,
                        default='../../../PX4-Autopilot/trace.swo'
                        )
    parser.add_argument('-e', '--elf',
                        help="<filename> Use this ELF file for information",
                        type=str,
                        default='../../../PX4-Autopilot/build/px4_fmu-v5x_default/px4_fmu-v5x_default.elf'
                        )

    return parser.parse_args()


if __name__ == "__main__":
    args = init_argparse()
    options = processOptions(args)
    orbethon(options)
