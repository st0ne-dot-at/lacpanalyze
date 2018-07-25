# LACPANALYZE
The lacpanalyze python script scans all ethernet interface for lacp packets and display interfaces with their lacp keys. Additionally it displays the native vlan on the interface.

## prerequisits
The tcpdump binary have to be installed.

## Example
    ./lacpanalyze.py
    INFO: scanning interfaces (p7p1,p7p2) for lacp port channels ... max 65 seconds
    INFO: match: 33048 on interface p7p1
    INFO: match: 33048 on interface p7p2
    {'33048': ['p7p1', 'p7p2']}
    INFO: scanning interfaces (p7p1,p7p2) for VLAN association ... max 65 seconds
    INFO: match: 466 on interface p7p1
    INFO: match: 466 on interface p7p2
    {'p7p1': '466', 'p7p2': '466'}

