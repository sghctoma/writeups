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

graph.node('0x40278e', 'Prison Collapsed.')
graph.node('0x4027af', 'nop')
graph.node('0x402923', 'if (0x400960(local_5, local_7) == 0) green')
graph.node('0x40252d', 'if (local_4 == 1) green')
graph.node('0x402611', 'if (local_0_4 < 2) green')
graph.node('0x4025d2', 'local_4++')
graph.node('0x402c03', 'if (0x400960(local_6, local_5) != 0) green')
graph.node('0x402851', 'if (local_5[0] != 0) green')
graph.node('0x402a05', 'Path Blocked!!')
graph.node('0x4027c5', 'if (local_4[0] < local_5[1]) green')
graph.node('0x402b26', 'if (local_50_1 == "s") green')
graph.node('0x402b75', 'Path Blocked!!')
graph.node('0x402961', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x403004', 'if (local_44 != "6a9e23f57e9f5590b0c168a781bf07c7") green')
graph.node('0x402d73', 'if (local_5[0] != local_5[1]) green')
graph.node('0x403328', 'if (local_4 < 40) green')
graph.node('0x402e6b', 'MD5_Final(local_34, local_19)\nSHA1_Final(local_38, local_31)\nlocal_4 = 0')
graph.node('0x402873', 'Prison Collapsed.')
graph.node('0x402cbb', 'if(0x400960(local_6, local_7) != 0) green')
graph.node('0x402dbd', 'if(local_6[0] != 0) green')
graph.node('0x402f44', 'local_4 = 0')
graph.node('0x4024e2', 'if (local_4 != 0) green')
graph.node('0x402abd', 'Path Blocked!!')
graph.node('0x402597', 'local_7 = calloc(1, 56)')
graph.node('0x4030dd', 'local_4++')
graph.node('0x403347', 'local_50[local_4] = local_50[local_4] ^ 0x604210[local_4]')
graph.node('0x40246d', 'if (local_3_4 > 3) green')
graph.node('0x40312e', 'if (local_3_4 == 2) green')
graph.node('0x402632', 'if (local_0_4 < 3) green')
graph.node('0x402501', 'local_5 = calloc(1, 56)')
graph.node('0x403077', 'if(local_40 < 40) green')
graph.node('0x402f1a', 'local_4++')
graph.node('0x4031df', 'local_50[local_4] = local_50[local_4] ^ 0x6040b0[local_4]')
graph.node('0x402a93', 'if(0x400960(local_7, local_6) != 0) green')
graph.node('0x402d4e', 'if (local_50_1 == "e") green')
graph.node('0x4025c3', 'nop')
graph.node('0x402df3', 'nop')
graph.node('0x402bde', 'if (local_50_1 == "z") green')
graph.node('0x402fc1', 'local_4++')
graph.node('0x402e20', 'nop')
graph.node('0x402e2f', 'nop')
graph.node('0x402a6e', 'if (local_50_1 == "w") green')
graph.node('0x40248c', 'Cell does not exist.')
graph.node('0x403096', 'local_50[local_4] = local_50[local_4] ^ 0x604160[local_4]')
graph.node('0x402c96', 'if (local_50_1 == "q") green')
graph.node('0x402fe5', 'if (local_3_4 == 1) green')
graph.node('0x4032b5', 'if(local_44 != "05aeebcadfe7f05a7e778d904d6d297e") green')
graph.node('0x4024ad', 'local_4 = 0')
graph.node('0x402a19', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x402cf9', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x402e02', 'nop')
graph.node('0x403061', 'local_4 = 0')
graph.node('0x40277f', 'nop')
graph.node('0x4033fe', 'ret')
graph.node('0x4029b6', 'if (local_50_1 == "d") green')
graph.node('0x402e3e', 'nop')
graph.node('0x40304d', 'Path Blocked!!')
graph.node('0x402b89', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x402653', 'if (local_0_4 == 3) green')
graph.node('0x4024c3', 'if (local_0_4 < 3) green')
graph.node('0x4031c0', 'if (local_4) < 40) green')
graph.node('0x402c2d', 'Path Blocked!!')
graph.node('0x402830', 'local_4++')
graph.node('0x402e11', 'nop')
graph.node('0x402e5c', 'nop')
graph.node('0x403101', 'flag: local_50')
graph.node('0x403312', 'local_4 = 0')
graph.node('0x40254c', 'local_6 = calloc(1, 56)')
graph.node('0x40294d', 'Path Blocked!!')
graph.node('0x402894', 'path input\nMD5_Init(local_19)\nSHA1_Init(local_31)')
graph.node('0x402ad1', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x402eb3', 'if (local_4 < 16) green')
graph.node('0x402d98', 'if (local_7[0] != local_7[1]) green')
graph.node('0x403196', 'Path Blocked!!')
graph.node('0x4027e7', 'local_5[local_5[0] + 1] = local_5[0]\nlocal_5[0]--')
graph.node('0x4025fc', 'local_0_4 = local_3_4')
graph.node('0x402c41', 'MD5_Update(local_19, local_50_1, 1)\nSHA1_Update(local_31, local_50_1, 1)')
graph.node('0x4033d1', 'flag: local_50')
graph.node('0x4031aa', 'local_4 = 0')
graph.node('0x4032fe', 'Path Blocked!!')
graph.node('0x4028de', 'scanf(local_50_1)\nif(local_50_1 == "a") green')
graph.node('0x402695', 'local_5[0] = 12\nlocal_5[1] = 12\nlocal_6[0] = 12\nlocal_6[1] = 12\nlocal_7[0] = 12\nlocal_7[1] = 12')
graph.node('0x402731', 'local_5[0] = 11\nlocal_5[1] = 11\nlocal_6[0] = 11\nlocal_6[1] = 11\nlocal_7[0] = 11\nlocal_7[1] = 11')
graph.node('0x402674', 'if (local_0_4 == 1) green')
graph.node('0x403296', 'if (local_3_4 == 3) green')
graph.node('0x402f79', 'sprintf(local_50[2 * local_4], "%02x", local_38[local_4]')
graph.node('0x402f5a', 'if (local_4 < 20) green')
graph.node('0x402ed2', 'sprintf(local_44[2 * local_4], "%02x", local_34[local_4]')
graph.node('0x4033ad', 'local_4++')
graph.node('0x403269', 'flag: local_50')
graph.node('0x402578', 'if (local_4 == 2) green')
graph.node('0x403245', 'local_4++')
graph.node('0x402e4d', 'nop')
graph.node('0x4029db', 'iif (0x400960(local_5, local_6) != 0) green')
graph.node('0x4026e3', 'local_5[0] = 10\nlocal_5[1] = 10\nlocal_6[0] = 10\nlocal_6[1] = 10\nlocal_7[0] = 10\nlocal_7[1] = 10')
graph.node('0x40244c', 'if (local_1 < 1) green')
graph.node('0x40314d', 'if (local_44 != "6dff819e14ce1bfc112d1817e69cff1f") green')
graph.node('0x402ddf', 'Path Blocked!!')
graph.node('0x402b4b', 'if (0x400960(local_7, local_5) != 0) green')
graph.node('0x402ce5', 'Path Blocked!!')

r = r2pipe.open('jail_break_bin')
r.cmd('s main')
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
        control, = (x for x in bb if 'mov dword [rbp-local_51]' in x['opcode'])
    except ValueError:
        continue

    if control['size'] == 6:
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

graph.render('jailbreak-plans')
