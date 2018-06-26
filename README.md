## Description
The purpose of abi-decompiler is to implement a simple tools to recover ABI of EVM smart contracts, including function names.

This side project is not yet a full Solidity decompiler, but it may be used as a helper tool during smart contract reverse engineering and security assessment.

The tool is written in Python2 and is equipped with several wordlists for function signature brute force.
Wordlists are compiled from real smart contracts and top 100k english words.
Also a signature database was imported from https://github.com/trailofbits/ethersplay.

## Usage

Arguments:
```
$ python abi-decompiler.py 
Usage: abi-decompiler.py [options]

Options:
  -h, --help            show this help message and exit
  -w DICT, --wordlist=DICT
                        input file function names list
  -f FILE, --file=FILE  file containing EVM bytecode
  -e EXHAUST, --exhaustive=EXHAUST
                        try only common types or all (0 / 1)
  -a ARGS, --args=ARGS  maximum number of function args
  -d DISASM, --disasm=DISASM
                        Only disassembly the bytecode (0 / 1)
  -v VERBOSE, --verbose=VERBOSE
                        Verbosity (0 - 2)
```

Example run:
```
$ python abi-decompiler.py -f /root/blockchain/contract.bin -w ./solnames1.txt
INFO:root:Starting to disassembly
DEBUG:root:Found function 28657aa5 at offset 103
DEBUG:root:Found function 2e1a7d4d at offset 146
DEBUG:root:Found function a5c12f79 at offset 191
DEBUG:root:Found function d87aa643 at offset 265
WARNING:root:Found functions: 28657aa5, 2e1a7d4d, a5c12f79, d87aa643
INFO:root:Now processing function 28657aa5
DEBUG:root:Processed 0 names
INFO:root:Now processing function 2e1a7d4d
DEBUG:root:Processed 0 names
WARNING:root:FOUND function 2e1a7d4d prototype: withdraw(uint256)
INFO:root:Now processing function a5c12f79
DEBUG:root:Processed 0 names
INFO:root:Now processing function d87aa643
DEBUG:root:Processed 0 names
WARNING:root:FOUND function d87aa643 prototype: invest(uint256,uint256)
==================================================
GENERATED ABI:
[{'constant': False,
  'inputs': [{'name': 'param1', 'type': 'uint256'},
             {'name': 'param2', 'type': 'uint256'}],
  'name': 'invest',
  'outputs': [],
  'payable': False,
  'stateMutability': 'nonpayable',
  'type': 'function'},
 {'constant': False,
  'inputs': [{'name': 'param1', 'type': 'uint256'}],
  'name': 'withdraw',
  'outputs': [],
  'payable': False,
  'stateMutability': 'nonpayable',
  'type': 'function'},
 {'constant': False,
  'inputs': [],
  'name': 'function_a5c12f79',
  'outputs': [],
  'payable': True,
  'stateMutability': 'payable',
  'type': 'function'},
 {'constant': False,
  'inputs': [],
  'name': 'function_28657aa5',
  'outputs': [],
  'payable': True,
  'stateMutability': 'payable',
  'type': 'function'}]
==================================================
GENERATED INTERFACE:
contract DecompiledContract {

    function invest(uint256 param1, uint256 param2) {}

    function withdraw(uint256 param1) {}

    function function_a5c12f79() payable {}

    function function_28657aa5() payable {}

}
```

Disassembly:
```
$ python abi-decompiler.py -f /root/blockchain/contract.bin -w ./solnames1.txt -d 1 | more
0x00000000	60...	PUSH1	0x80
0x00000002	60...	PUSH1	0x40
0x00000004	52	MSTORE
0x00000005	60...	PUSH1	0x40
0x00000007	51	MLOAD
0x00000008	60...	PUSH1	0x40
0x0000000A	80	DUP1
0x0000000B	61...	PUSH2	0x9407
0x0000000E	83	DUP4
0x0000000F	39	CODECOPY
0x00000010	81	DUP2
0x00000011	1	ADD
0x00000012	80	DUP1
0x00000013	60...	PUSH1	0x40
0x00000015	52	MSTORE
0x00000016	81	DUP2
0x00000017	1	ADD
0x00000018	90	SWAP1
```

## Known bugs

This tool was meant to keep very simple, that's why there's no fancy clever mathematical analysis, symbolic execution.

This means that this dirty tool lacks some features and cannot accurately calculate some features (types of return value, payable modifier).

I will try to solve this challenge and make it work without huge dependencies =)