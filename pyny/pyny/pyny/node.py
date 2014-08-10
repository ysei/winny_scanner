'''Winny Node.
'''
#
# Copyright (c) 2006 Pyny Project.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id: $
#

import rc4
from nyexcept import *
from conv import hexstr, binary

__all__ = ['Node']
__version__ = "$Revision: $"


class Node:
    '''Winny Node.
    '''

    def __init__(self, s):
        pass


def RC4Key(checksum):
    '''RC4 key virtual class.
    '''
    magic = '\x6f\x70\x69\x65\x77\x66\x36\x61\x73\x63\x78\x6c\x76'
    return chr(checksum) + magic[1:]

def pack_hash(inetaddrss):
    '''Pack internet address.

    n.n.n.n:s -> @xxxx....

    sample:
    >>> pack_hash('123.1.2.3:1234')
    '@ba9582a383c7d6e79cd5d8c71f7347'
    '''
    checksum = 0
    for i in inetaddrss:
        checksum = (checksum + ord(i)) & 0xFF
    rc4key = RC4Key(checksum)
    hash = '@' + hexstr(chr(checksum) + rc4.crypt(rc4key, inetaddrss))
    return hash

def unpack_hash(hash):
    '''Unpack winny node format.

    @xxxx.... -> n.n.n.n:s

    sample:
    >>> unpack_hash('@ba9582a383c7d6e79cd5d8c71f7347')
    '123.1.2.3:1234'
    '''
    if len(hash) < 20:    # len('@^') + len('0.0.0.0:0') * 2 = 20
        raise NodeFormatError('Specified hash-string is too small')
    elif not hash.startswith('@'):
        raise NodeFormatError(
            'Specified hash-string is not hash-string of NodeAddress')

    sum = binary(hash[1:3])
    encoded = binary(hash[3:])
    rc4key = RC4Key(ord(sum))
    unpackedstr = rc4.crypt(rc4key, encoded)

    checksum = 0
    for i in unpackedstr:
        checksum += ord(i)
    if (checksum & 0xFF) != ord(sum):
        raise NodeFormatError('sum check error')
    return unpackedstr

def _test():
    import doctest, node
    return doctest.testmod(node)

if __name__ == '__main__':
    _test()
