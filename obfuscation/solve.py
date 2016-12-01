#!/usr/bin/env python

import angr

def main():
    p = angr.Project('./obfuscate')
    ex = p.surveyors.Explorer(find=(0x080484C5, ), avoid=(0x0804849E, ))
    ex.run()

    return ex.found[0].state.posix.dumps(0).strip('\0\n')

if __name__ == '__main__':
    print main()