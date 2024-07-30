# FMD IDA processor module
This module introduces support for Chinese MCUs manufactured by Fremont Micro Devices (FMD) to IDA. As is the Chinese custom, there is very little information about these MCUs. If there are any datasheets you're looking for, they are in Chinese and often quite vague. All information for this project was gathered by reverse engineering of various FMD tools.

For now, only 8-bit MCUs of F-Series are supported. Tested on FT61F04x.

## Installation
Just copy *fmd.py* file to IDA's *procs* directory. Tested on IDA versions 7.6 and 7.7.