#!/usr/bin/env python

import random
import tyrell.spec as S
from tyrell.interpreter import PostOrderInterpreter, GeneralError
from tyrell.enumerator import SmtEnumerator, RelaxedRandomEnumerator
from tyrell.decider import Example, ExampleConstraintDecider, ExampleConstraintPruningDecider
from tyrell.synthesizer import Synthesizer
from tyrell.logger import get_logger

logger = get_logger('tyrell')

class DecryptionInterpreter(PostOrderInterpreter):

    def eval_get_int(self, node, args):
        return int(args[0])

    def eval_caesar(self, node, args):
        arg_bits = args[0]
        arg_key = args[1]
        if len(arg_bits)%7 != 0:
            raise GeneralError()
        ct_set = set(arg_bits)
        if not (ct_set == {'0','1'} or ct_set == {'0'} or ct_set == {'1'}):
            raise GeneralError()
        res = ''
        for i in range(len(arg_bits)//7):
            dec_value = int(arg_bits[i*7:i*7+7],2)
            res = res + format((dec_value-arg_key)%128, '07b')       
        return res

    def eval_one_time_pad(self, node, args):
        arg_bits = args[0]
        arg_key = args[1]
        if len(arg_bits)%7 != 0:
            raise GeneralError()
        ct_set = set(arg_bits)
        if not (ct_set == {'0','1'} or ct_set == {'0'} or ct_set == {'1'}):
            raise GeneralError()
        random.seed(arg_key)
        res = ''
        for i in range(len(arg_bits)//7):
            dec_value = format(int(arg_bits[i*7:i*7+7],2)^random.randint(0,127),'07b')
            res = res + dec_value
        return res

    def eval_prf_scheme(self, node, args):
        arg_bits = args[0]
        arg_key = args[1]
        if len(arg_bits)%14 != 0:
            raise GeneralError()
        ct_set = set(arg_bits)
        if not (ct_set == {'0','1'} or ct_set == {'0'} or ct_set == {'1'}):
            raise GeneralError()
        res = ''
        for i in range(len(arg_bits)//14):
            r = int(arg_bits[i*14:i*14+7],2)
            k = arg_key
            for j in range(7):
                random.seed(k)
                k = random.randint(0,16383)
                k = k % 128 if r % 2 == 0 else k // 128
                r = r // 2
            res = res + format(int(arg_bits[i*14+7:i*14+14],2)^k, '07b')
        return res
        
    def eval_bit_to_string(self, node, args):
        arg_bits = args[0]
        ct_set = set(arg_bits)
        if not (ct_set == {'0','1'} or ct_set == {'0'} or ct_set == {'1'}):
            raise GeneralError()
        if len(arg_bits)%7 != 0:
            raise GeneralError()
        return ''.join(chr(int(arg_bits[i*7:i*7+7],2)) for i in range(len(arg_bits)//7))


# encryption functions
        
def enc_caesar(message, key):
    res = ''
    for c in message:
        res = res + format((ord(c)+key)%128, '07b')
    return res

def enc_one_time_pad(message, key):
    random.seed(key)
    res = ''
    for c in message:
        res = res + format(ord(c)^random.randint(0,127), '07b')
    return res

def enc_prf_scheme(message, key):
    res = ''
    for c in message:
        gen = random.randint(0,127)
        r = gen
        k = key
        res = res + format(gen, '07b')
        for i in range(7):
            random.seed(k)
            k = random.randint(0,16383)
            k = k % 128 if r % 2 == 0 else k // 128
            r = r // 2
        res = res + format(ord(c)^k, '07b')
    return res

def main():
    print(enc_prf_scheme('hello world', 36))
    logger.info('Parsing Spec...')
    # TBD: parse the DSL definition file and store it to `spec`
    spec = S.parse_file('./crypto_synth/crypto_synth.tyrell')
    logger.info('Parsing succeeded')

    logger.info('Building synthesizer...')
    synthesizer = Synthesizer(
        enumerator=RelaxedRandomEnumerator(spec, max_depth=5, min_depth=0, seed=None),
        decider=ExampleConstraintDecider(
            spec=spec, # TBD: provide the spec here
            interpreter=DecryptionInterpreter(),
            examples=[
                # enc_caesar('CS190I Program Synthesis', 52)
                # Example(input = ['111011100001111100101110110111001001111101101010000'+
                #                  '001000100110010001100110110100110001010101000011010'+
                #                  '100000011101011010100010010100000111000011001010011'+
                #                  '100111010100111'], 
                #         output = 'CS190I Program Synthesis')

                # enc_one_time_pad('decrypting messages', 121)
                # Example(input = ['111001010100100000110101111110101000100100011110110'+
                #                  '001100000010110100110011101001100110001100010110011'+
                #                  '1100110111001010010111111010101'], 
                #         output = 'decrypting messages')
                
                # enc_prf_scheme('hello world', 36)
                Example(input = ['001001101010001100100110110111011010100110000011110'+
                                 '101111010000000110101011100001001000001000110001001'+
                                 '0011011010100001011110111001001101100110000101101101'], 
                        output='hello world')
            ],
        )
    )
    logger.info('Synthesizing programs...')

    prog = synthesizer.synthesize()
    if prog is not None:
        logger.info('Solution found: {}'.format(prog))
    else:
        logger.info('Solution not found!')


if __name__ == '__main__':
    logger.setLevel('DEBUG')
    main()

