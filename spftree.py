#!/bin/env python3
import typer
import sys
import dns.resolver

spf_keywords = ['all', 'a', 'ip4', 'ip6', 'mx',
                'ptr', 'exists', 'include', 'v=spf1', '"v=spf1']


def get_spf_from_zone(zone: str, timeout: float = 1.0):
    """
    Get SPF record from zone by checking if the TXT record contains 
    valid spf keywords or mechanisms.
    """
    try:
        # FIXME get to many timeouts for now, always after 5.4 sec.
        # setting resolver.timeout = timeout does not change the timeout.
        resolver = dns.resolver
        resolver.nameservers = ['1.1.1.1', '1.0.0.1']
        spf = resolver.resolve(zone, 'TXT', raise_on_no_answer=False)
        for record in spf:
            if str(record).split()[0] in spf_keywords:
                return record
    except Exception as e:
        typer.echo(f"Error: {zone} {e}", err=sys.stderr)
        typer.Abort()


def spftree(zone: str, indent: int = 0):
    """
    Create a tree structure of the zones SPF record
    """
    record = get_spf_from_zone(zone)

    # FIXME Combine records with multiple strings
    # It can possbily be n number of strings
    if len(record.strings) > 1:
        spf_record = record.strings[0] + record.strings[1]
    else:
        spf_record = record.strings[0]

    for field in spf_record.split():
        field = field.decode()
        typer.echo(' ' * indent + field)
        if field.find('include:') != -1:
            nextzone = field[field.index(':')+1:]
            spftree(nextzone, indent+2)


if __name__ == "__main__":
    typer.run(spftree)
