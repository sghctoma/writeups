#!/usr/bin/env python

import r2pipe
import json
from graphviz import Digraph


graph_attr = {'splines': 'ortho'}
node_attr = {'shape': 'box',
        'style': 'filled', 
        'fillcolor': 'lightgray',
        'fontname': 'Courier',
        'fontsize': '10',}

graph = Digraph(format='png', graph_attr=graph_attr, node_attr=node_attr)

graph.node('0x400d80', 'ret local_1_4')
graph.node('0x400ba4', 'if (local_1_4 != 0) green')
graph.node('0x400c02', 'if (arg2[0] == arg2[1]) green')
graph.node('0x400d6d', 'local_1_4 = 1')
graph.node('0x400c24', 'arg2[arg2[0] + 1] = arg1[arg1[0] + 2]\n++arg1[0]\n--arg2[0]\nlocal_1_4 = 0')
graph.node('0x400bc1', 'if (arg1[0] < arg1[1]) green')
graph.node('0x400c9d', 'if (arg1[arg1[0] + 2] < arg2[arg2[0] + 2]) green')
graph.node('0x400d61', 'nop')
graph.node('0x400cd0', 'arg2[arg2[0] + 1] = arg1[arg1[0] + 2]\n++arg1[0]\n--arg2[0]\nlocal_1_4 = 0')
graph.node('0x400d49', 'nop')
graph.node('0x400be3', 'if (arg2[0] != 0) green')
graph.node('0x400b84', 'if (arg1 != 0) green', peripheries = '2')
graph.node('0x400d55', 'nop')

r = r2pipe.open('jail_break_bin')
r.cmd('aaa')
r.cmd('s 0x00400960')
jes = r.cmd('pdf~je[1,4]')

controls = {}
for je in jes.splitlines():
    offset, jump = map(lambda x:int(x, 16), je.split(' '))

    bb = r.cmdj('pdbj @' + str(offset))
    try:
        sub, = (x for x in bb if 'sub eax, ' in x['opcode'])
        control = int(sub['opcode'].split(',')[1], 16)
        controls[control] = jump

    except ValueError:
        print('[WARN] Basic block at 0x%08x needs attention!' % bb[0]['offset'])
        continue

for offset in controls.values():
    bb = r.cmdj('pdbj @' + str(offset))
    try:
        control, = (x for x in bb if 'mov dword [rbp-local_4_4]' in x['opcode'])
    except ValueError:
        continue

    if control['size'] == 3:
        try:
            cmov, = (x for x in bb if x['type'] == 'cmov')
        except ValueError:
            print('[WARN] Basic block at 0x%08x needs attention!' % bb[0]['offset'])
            continue

        s = cmov['opcode'].split(' ')
        r1 = s[1][:-1]
        r2 = s[2]
        w1, = (x['opcode'] for x in bb if ('mov %s, 0x' % r1) in x['opcode'])
        w2, = (x['opcode'] for x in bb if ('mov %s, 0x' % r2) in x['opcode'])
        c1 = int(w1.split(',')[1], 16)
        c2 = int(w2.split(',')[1], 16)
        graph.edge('0x%06x' % offset, '0x%06x' % controls[c1], color = 'red')
        graph.edge('0x%06x' % offset, '0x%06x' % controls[c2], color = 'green')
    else:
        c = int(control['opcode'].split(',')[1], 16)
        graph.edge('0x%06x' % offset, '0x%06x' % controls[c])

graph.render('checkstep')
