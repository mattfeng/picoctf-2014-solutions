#!/usr/bin/env python

import angr

def main():
    p = angr.Project("./bitpuzzle", load_options={'auto_load_libs': False})
    ex = p.surveyors.Explorer(find=(0x080486ba, ), avoid=(0x080486d0, ))
    ex.run()

    return ex.found[0].state.posix.dumps(0).strip('\0\n')

if __name__ == '__main__':
    print main()