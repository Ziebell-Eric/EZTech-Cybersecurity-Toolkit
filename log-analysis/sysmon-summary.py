#!/usr/bin/env python3
"""Summarize exported Sysmon XML events. Read-only/offline analysis."""
import argparse, collections, xml.etree.ElementTree as ET
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('xml', type=Path, help='Sysmon events exported as XML')
a=p.parse_args()
root=ET.parse(a.xml).getroot()
counts=collections.Counter(); images=collections.Counter(); destinations=collections.Counter()
for event in root.iter():
    if not event.tag.endswith('Event'): continue
    eid=None; fields={}
    for node in event.iter():
        if node.tag.endswith('EventID') and eid is None: eid=(node.text or '').strip()
        if node.tag.endswith('Data'):
            name=node.attrib.get('Name');
            if name: fields[name]=node.text or ''
    if eid:
        counts[eid]+=1
        if fields.get('Image'): images[fields['Image']]+=1
        if fields.get('DestinationIp'): destinations[fields['DestinationIp']]+=1
print('Sysmon event IDs:')
for k,v in counts.most_common(): print(f'{k:>5} {v:8}')
print('\nTop process images:')
for k,v in images.most_common(20): print(f'{v:8} {k}')
print('\nTop destination IPs:')
for k,v in destinations.most_common(20): print(f'{v:8} {k}')
