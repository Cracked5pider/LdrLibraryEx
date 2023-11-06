#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import sys

# this is by Austin from https://github.com/SecIdiot/TitanLdr/blob/master/python3/hashstring.py. Full credit goes to him.

def hash_string( string ):
    try:
        hash = 5381

        for x in string.upper():
            hash = (( hash << 5 ) + hash ) + ord(x)

        return hash & 0xFFFFFFFF
    except:
        pass

if __name__ in '__main__':
    try:
        print('#define H_API_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_string( sys.argv[ 1 ] ) ));
    except IndexError:
        print('usage: %s [string]' % sys.argv[0])