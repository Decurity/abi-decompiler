import itertools
import logging
import re

from collections import defaultdict
from optparse import OptionParser
from pprint import pprint

import sha3

__author__ = 'Beched'
__version__ = '0.1'


def disasm(code):
    # the simpliest disasm ever
    opcodes = ['STOP', 'ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD', 'ADDMOD', 'MULMOD', 'EXP', 'SIGNEXTEND', '',
               '', '', '', 'LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO', 'AND', 'OR', 'XOR', 'NOT', 'BYTE', '', '', '', '',
               '', 'SHA3', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'ADDRESS', 'BALANCE', 'ORIGIN',
               'CALLER', 'CALLVALUE', 'CALLDATALOAD', 'CALLDATASIZE', 'CALLDATACOPY', 'CODESIZE', 'CODECOPY',
               'GASPRICE', 'EXTCODESIZE', 'EXTCODECOPY', '', '', '', 'BLOCKHASH', 'COINBASE', 'TIMESTAMP', 'NUMBER',
               'DIFFICULTY', 'GASLIMIT', '', '', '', '', '', '', '', '', '', '', 'POP', 'MLOAD', 'MSTORE', 'MSTORE8',
               'SLOAD', 'SSTORE', 'JUMP', 'JUMPI', 'PC', 'MSIZE', 'GAS', 'JUMPDEST', '', '', '', '', 'PUSH1', 'PUSH2',
               'PUSH3', 'PUSH4', 'PUSH5', 'PUSH6', 'PUSH7', 'PUSH8', 'PUSH9', 'PUSH10', 'PUSH11', 'PUSH12', 'PUSH13',
               'PUSH14', 'PUSH15', 'PUSH16', 'PUSH17', 'PUSH18', 'PUSH19', 'PUSH20', 'PUSH21', 'PUSH22', 'PUSH23',
               'PUSH24', 'PUSH25', 'PUSH26', 'PUSH27', 'PUSH28', 'PUSH29', 'PUSH30', 'PUSH31', 'PUSH32', 'DUP1', 'DUP2',
               'DUP3', 'DUP4', 'DUP5', 'DUP6', 'DUP7', 'DUP8', 'DUP9', 'DUP10', 'DUP11', 'DUP12', 'DUP13', 'DUP14',
               'DUP15', 'DUP16', 'SWAP1', 'SWAP2', 'SWAP3', 'SWAP4', 'SWAP5', 'SWAP6', 'SWAP7', 'SWAP8', 'SWAP9',
               'SWAP10', 'SWAP11', 'SWAP12', 'SWAP13', 'SWAP14', 'SWAP15', 'SWAP16', 'LOG0', 'LOG1', 'LOG2', 'LOG3',
               'LOG4', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
               '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
               '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
               'CREATE', 'CALL', 'CALLCODE', 'RETURN', '', '', '', '', '', '', '', '', '', '', '', 'SUICIDE']
    code = map(ord, code)
    listing = ''
    ip = 0
    while ip < len(code):
        opcode = code[ip]
        print '0x%08X\t' % ip,
        # print opcodes[opcode] or 'INVALID',
        if 0x60 <= opcode < 0x80:  # push
            size = opcode - 0x5f
            # print '%s\t' % ''.join([hex(x)[2:] for x in code[ip:ip + size]]),
            print hex(opcode)[2:] + '...\t',
            try:
                value = hex(sum([code[ip + i + 1] << (8 * i) for i in xrange(size)])).rstrip('L')
            except:
                value = hex((1 << (8 * size)) - 1).rstrip('L')
            instruction = '%s\t%s' % (opcodes[opcode], value)
            ip += size
        else:
            # print ''
            print hex(opcode)[2:] + '\t',
            instruction = opcodes[opcode] or 'INVALID'
        print instruction
        listing += instruction + '\n'
        ip += 1
    return listing


def find_functions(code):
    logging.info('Starting to disassembly')
    code = map(ord, code)
    functions = []
    i = 0
    while i < len(code):
        opcode = code[i]
        if opcode == 0x63:  # push4
            value = code[i + 1:i + 5]
            # an awful heuristic below
            if i + 10 < len(code):
                # (dup*), eq, push2, jumpi
                # if re.match('.?\x14\x61..\x57', code[i:i + 10])
                for off in xrange(2):
                    if code[i + off + 5] == 0x14 \
                            and code[i + off + 6] == 0x61 \
                            and code[i + off + 9] == 0x57:
                        offset = code[i + off + 7] * 256 + code[i + off + 8]
                        name = ''.join(map(chr, value))
                        logging.debug('Found function %s at offset %s' % (name.encode('hex'), offset))
                        functions.append((offset, name))
                        break
            i += 4
        elif 0x60 <= opcode < 0x80:  # push
            i += opcode - 0x5f
        i += 1
    return functions


def brute_prototype(function, dict_file, max_args=3, exhaustive=False):
    logging.info('Now processing function %s' % function.encode('hex'))
    argtypes = ['bool', 'address', 'bytes', 'string']
    if exhaustive:
        argtypes += ['int%s' % x for x in xrange(8, 257, 8)]
        argtypes += ['uint%s' % x for x in xrange(8, 257, 8)]
        argtypes += ['bytes%s' % x for x in xrange(1, 33)]
    else:
        argtypes += ['bytes8', 'bytes16', 'bytes32', 'uint256', 'int256']
    with open(dict_file, 'r') as names:
        counter = 0
        for name in names:
            if counter % 1000 == 0:
                logging.debug('Processed %s names' % counter)
            for argnum in xrange(max_args + 1):
                for signature in itertools.product(argtypes, repeat=argnum):
                    prototype = '%s(%s)' % (name.strip(), ','.join(signature))
                    if sha3.keccak_256(prototype).digest()[:4] == function:
                        logging.warning('FOUND function %s prototype: %s' % (function.encode('hex'), prototype))
                        return prototype
            counter += 1


def process(code_file, dict_file, max_args, exhaust):
    code = open(code_file, 'rb').read()
    funcs = find_functions(code)
    logging.warning('Found functions: %s' % ', '.join([x[1].encode('hex') for x in funcs]))
    res = defaultdict(defaultdict)
    for func in funcs:
        prototype = brute_prototype(func[1], dict_file, max_args, exhaust)
        if prototype is not None:
            res[func[0]]['prototype'] = prototype
        else:
            res[func[0]]['prototype'] = 'function_%s()' % func[1].encode('hex')
    abi = generate_abi(code, res)
    print '=' * 50
    print 'GENERATED ABI:'
    pprint(abi)
    print '=' * 50
    print 'GENERATED INTERFACE:'
    print generate_interface(abi)


def generate_abi(code, data):
    offsets = sorted(data.keys())
    offsets.append(len(code))
    for i in xrange(len(offsets) - 1):
        # this is also awful heuristic
        body = code[offsets[i]:offsets[i + 1]]
        # print body.encode('hex')
        if re.search(r'\x34.?\x15\x61..\x57', body, re.S):
            data[offsets[i]]['payable'] = False
        else:
            data[offsets[i]]['payable'] = True
        data[offsets[i]]['returns'] = '\xf3' in body
    abi = []
    for func in data.values():
        record = defaultdict()
        record['type'] = 'function'
        record['constant'] = False
        record['name'] = func['prototype'].split('(')[0]
        record['inputs'] = []
        for i, input_type in enumerate(func['prototype'].split('(')[1][:-1].split(',')):
            if input_type == '':
                break
            record['inputs'].append({'name': 'param%s' % (i + 1), 'type': input_type})
        record['stateMutability'] = 'payable' if func['payable'] else 'nonpayable'
        record['payable'] = func['payable']
        # TODO: find return types
        record['outputs'] = []
        '''if func['returns']:
            records['outputs'].append({'name': '', 'type': ''})'''
        abi.append(dict(record))
    return abi


def generate_interface(abi):
    txt = 'contract DecompiledContract {\n\n'
    for record in abi:
        args = ', '.join([arg['type'] + ' ' + arg['name'] for arg in record['inputs']])
        payable = 'payable ' if record['payable'] else ''
        txt += '    function %s(%s) %s{}\n\n' % (record['name'], args, payable)
    txt += '}'
    return txt


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-w', '--wordlist', dest='dict',
                      help='input file function names list')
    parser.add_option('-f', '--file', dest='file',
                      help='file containing EVM bytecode')
    parser.add_option('-e', '--exhaustive', dest='exhaust', default=0, type='int',
                      help='try only common types or all (0 / 1)')
    parser.add_option('-a', '--args', dest='args', default=3, type='int',
                      help='maximum number of function args')
    parser.add_option('-d', '--disasm', dest='disasm', default=0, type='int',
                      help='Only disassembly the bytecode (0 / 1)')
    parser.add_option('-v', '--verbose', dest='verbose', default=2, type='int',
                      help='Verbosity (0 - 2)')

    (opts, _) = parser.parse_args()

    if not opts.file or not (opts.dict or opts.disasm):
        parser.print_help()
        quit()

    if opts.verbose == 0:
        logging.basicConfig(level=logging.WARNING)
    elif opts.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif opts.verbose == 2:
        logging.basicConfig(level=logging.DEBUG)

    if opts.disasm:
        disasm(open(opts.file, 'rb').read())
    else:
        process(opts.file, opts.dict, opts.args, opts.exhaust)
