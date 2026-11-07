#!/usr/bin/env python3
"""Local, finite evaluation of the captured IPv4 INPUT path; never executes nft.

This is a static packet inference from two non-atomic readonly observations.
It does not attribute existing counters to our probes or prove a live connection.
Unknown expressions/options fail; no firewall data is changed.
"""
import hashlib
import ipaddress
import json
import re
import shlex
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent / 'firewall-r1-private'
NFT_PIN = '3ae405444a87f0b4ff0bc21d8e000558529c037b179318e0ba5591a8a321cfef'
IPT_PIN = '6d1824203ec159628cad0cf6c808f3b278263b9c5c88f7aa42fd15ad47501a68'


def need(value, code):
    if not value:
        raise RuntimeError(code)


def member(value, expected):
    if isinstance(expected, dict):
        if set(expected) == {'prefix'}:
            prefix = expected['prefix']
            return ipaddress.ip_address(value) in ipaddress.ip_network(str(prefix['addr'])+'/'+str(prefix['len']))
        if set(expected) == {'set'}:
            return any(member(value, part) for part in expected['set'])
        if set(expected) == {'range'}:
            low, high = expected['range']
            return low <= value <= high
        raise RuntimeError('unhandled_nft_rhs')
    return value == expected


def nft_match(expr, packet):
    need(set(expr) == {'match'}, 'unhandled_nft_expression')
    match = expr['match']; left = match['left']; right = match['right']
    need(match['op'] in ('==', '!='), 'unhandled_nft_operator')
    if set(left) == {'meta'}:
        key = left['meta']['key']
        need(key in ('iif', 'iifname', 'nfproto', 'l4proto'), 'unhandled_nft_meta')
        value = {'iif': 'enp0s25', 'iifname': 'enp0s25', 'nfproto': 'ipv4', 'l4proto': 'tcp'}[key]
    elif set(left) == {'payload'}:
        payload = left['payload']; proto, field = payload['protocol'], payload['field']
        need(proto in ('ip', 'ip6', 'tcp', 'udp'), 'unhandled_nft_protocol')
        if proto in ('ip6', 'udp'):
            return False
        values = {'ip': {'saddr': packet['src'], 'daddr': packet['dst'], 'protocol': 'tcp'},
                  'tcp': {'dport': packet['dport']}}
        need(field in values[proto], 'unhandled_nft_payload_field')
        value = values[proto][field]
    else:
        raise RuntimeError('unhandled_nft_lhs')
    result = member(value, right)
    return result if match['op'] == '==' else not result


def nft_verdict(chain, rows, packet):
    for ordinal, row in enumerate(rows):
        expressions = row['expr']
        conditions = [expr for expr in expressions if 'match' in expr]
        verdicts = [expr for expr in expressions if 'match' not in expr]
        need(len(verdicts) == 1 and set(verdicts[0]) in ({'accept'}, {'reject'}), 'unhandled_inet_verdict')
        if all([nft_match(expr, packet) for expr in conditions]):
            return {'verdict': next(iter(verdicts[0])).upper(), 'handle': row['handle'],
                    'ordinal': ordinal, 'matchedExpressions': conditions}
    return {'verdict': chain['policy'].upper(), 'policyFallback': True}


def port_member(port, value):
    return any(int(a) <= port <= int(b) if ':' in term else port == int(term)
               for term in value.split(',') for a, _, b in [term.partition(':')])


def ipt_condition(tokens, packet):
    matched = True; invert = False; index = 0
    while index < len(tokens):
        key = tokens[index]; index += 1
        if key == '!':
            need(not invert, 'duplicate_negation'); invert = True; continue
        need(index < len(tokens), 'missing_iptables_option_value')
        value = tokens[index]; index += 1
        if key == '-m':
            need(value in ('tcp','udp','icmp','conntrack','addrtype','comment','multiport'), 'unknown_iptables_module')
            need(not invert, 'negated_module'); continue
        if key == '--comment':
            need(not invert, 'negated_comment'); continue
        if key == '-p': result = value == 'tcp'
        elif key == '-i': result = value == 'enp0s25'
        elif key in ('-s', '-d'):
            result = ipaddress.ip_address(packet['src' if key == '-s' else 'dst']) in ipaddress.ip_network(value)
        elif key in ('--dport', '--dports'): result = port_member(packet['dport'], value)
        elif key == '--sport':
            need('-p' in tokens and tokens[tokens.index('-p')+1] == 'udp', 'unhandled_tcp_sport')
            result = False  # The observed UDP DHCP row cannot match our TCP packet.
        elif key == '--ctstate': result = 'NEW' in value.split(',')
        elif key == '--dst-type': result = value == 'LOCAL'
        elif key == '--icmp-type': result = False
        else: raise RuntimeError('unhandled_iptables_option:'+key)
        matched = matched and (not result if invert else result); invert = False
    need(not invert, 'trailing_negation')
    return matched


def walk_iptables(chain, rules, packet, trace, stack=()):
    need(chain not in stack and len(stack) < 20, 'iptables_cycle')
    for ordinal, row in enumerate(rules[chain]):
        target = row['target']
        need(not row['targetOptions'] or target in ('LOG','REJECT'), 'unexpected_target_options')
        if target == 'LOG':
            # Logging and its rate limit cannot change the packet verdict.
            continue
        if not ipt_condition(row['conditions'], packet): continue
        trace.append({'chain': chain, 'ordinal': ordinal, 'target': target, 'counter': row['counter']})
        if target in ('ACCEPT', 'DROP', 'REJECT', 'RETURN'): return target
        need(target in rules, 'unknown_iptables_jump')
        result = walk_iptables(target, rules, packet, trace, (*stack, chain))
        if result != 'RETURN': return result
    return 'DROP' if chain == 'INPUT' else 'RETURN'


def main():
    nft = (ROOT/'nft.ruleset.original.private.log').read_bytes()
    ipt = (ROOT/'iptables-filter.original.private.log').read_bytes()
    need(hashlib.sha256(nft).hexdigest() == NFT_PIN and hashlib.sha256(ipt).hexdigest() == IPT_PIN, 'original_byte_pins')
    text = nft.decode(); data = json.loads(text[text.index('{'):])['nftables']
    chains = {(x['chain']['family'], x['chain']['table'], x['chain']['name']):x['chain'] for x in data if 'chain' in x}
    nrules = defaultdict(list)
    for entry in data:
        if 'rule' in entry:
            rule = entry['rule']; nrules[(rule['family'],rule['table'],rule['chain'])].append(rule)
    input_chain = chains[('ip','filter','INPUT')]
    need(input_chain['policy'] == 'drop', 'observed_ipv4_input_drop')
    irules = {}; declarations = []; raw_user = []
    for line in ipt.decode().splitlines():
        if line.startswith(':'):
            name = line.split()[0][1:]; irules[name] = []; declarations.append(line); continue
        match = re.fullmatch(r'\[(\d+):(\d+)\] -A (\S+) (.+)', line)
        if not match: continue
        packets, count, chain, rest = match.groups(); tokens = shlex.split(rest)
        need('-j' in tokens and '-g' not in tokens, 'observed_jump_shape')
        split = tokens.index('-j'); target = tokens[split+1]
        # Only the reached INPUT closure is evaluated; other tables' actions are not executed.
        row={'target':target,'targetOptions':tokens[split+2:],'conditions':tokens[:split],
             'counter':{'packets':int(packets),'bytes':int(count)}}
        irules[chain].append(row)
        if chain == 'ufw-user-input': raw_user.append(row)
    need(any(x.startswith(':INPUT DROP ') for x in declarations) and len(raw_user) == 4, 'exact_observed_user_input_shape')
    inet_keys = [('inet','hepta_broker_ingress_v1','input'),('inet','cloudflare-warp','input')]
    results=[]
    for source in ('192.168.0.8','192.168.0.11'):
        for port in (22,46230,31040,31041):
            packet={'src':source,'dst':'192.168.0.13','dport':port}; trace=[]
            verdict=walk_iptables('INPUT',irules,packet,trace)
            inet=[{'family':key[0],'table':key[1],'chain':key[2],
                   **nft_verdict(chains[key],nrules[key],packet)} for key in inet_keys]
            results.append({'assumedNewLocalTcpPacket':packet,'ingressInterface':'enp0s25','ctStateAssumption':'NEW',
                            'ipv4FilterVerdict':verdict,'ipv4Path':trace,'inetBaseChainVerdicts':inet,
                            'allEvaluatedInputChainsAccept':verdict=='ACCEPT' and all(x['verdict']=='ACCEPT' for x in inet)})
    report={'schema':'heptabao.x230-fixed-firewall-static-path-projection.r1',
            'rawPrivateSources':{'nft':{'bytes':len(nft),'sha256':NFT_PIN},'iptablesFilter':{'bytes':len(ipt),'sha256':IPT_PIN}},
            'rulesChanged':False,'privateOriginalRulesPublished':False,'unknownExpressionsIgnored':False,
            'observationsAreNotAtomic':True,'staticInferenceOnly':True,'livePortConnectivityProved':False,
            'counterDeltasNotMeasuredOrAttributedToOurProbe':True,'userInputChainTotalRuleCount':4,
            'existingLanAllowedTcpPorts':{'source':'192.168.0.0/24','range':[31000,31099]},'packets':results}
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__ == '__main__': main()
