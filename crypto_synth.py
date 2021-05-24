#!/usr/bin/env python

import tyrell.spec as S
from tyrell.interpreter import PostOrderInterpreter, GeneralError
from tyrell.enumerator import SmtEnumerator, RelaxedRandomEnumerator
from tyrell.decider import Example, ExampleConstraintDecider, ExampleConstraintPruningDecider
from tyrell.synthesizer import Synthesizer
from tyrell.logger import get_logger

logger = get_logger('tyrell')

class EncryptionInterpreter(PostOrderInterpreter):

    def eval_get_int(self, node, args):
        return int(args[0])

    def eval_vinegere(self, node, args):
        arg_bits = args[0]
        arg_key = args[1]
        res = ''
        for i in range(len(arg_bits)//7):
            dec_value = (int(arg_bits[i*7:i*7+7],2)-arg_key)%128
            res = res + bin(dec_value).replace('0b', '')       
        return res

    def eval_bit_to_string(self, node, args):
        arg_bits = args[0]
        return ''.join(chr(int(arg_bits[i*7:i*7+7],2)) for i in range(len(arg_bits)//7))



def main():
    logger.info('Parsing Spec...')
    # TBD: parse the DSL definition file and store it to `spec`
    spec = S.parse_file('crypto_synth/crypto_synth.tyrell')
    logger.info('Parsing succeeded')

    logger.info('Building synthesizer...')
    synthesizer = Synthesizer(
        enumerator=RelaxedRandomEnumerator(spec, max_depth=3, min_depth=0, seed=None),
        decider=ExampleConstraintDecider(
            spec=spec, # TBD: provide the spec here
            interpreter=EncryptionInterpreter(),
            examples=[
                Example(input=[''.join(bin(ord(x)).replace('0b','') for x in 'e')], output='d')
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
