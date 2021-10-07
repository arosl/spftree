#!/usr/bin/env python3
import typer
import sys
import dns.resolver

spf_keywords = ['all', 'a', 'ip4', 'ip6', 'mx',
                'ptr', 'exists', 'include', 'redirect', 'v=spf1', '"v=spf1']
spf_modifiers = ['+', '-', '~', '?']

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
        typer.secho(f"Error: {zone} {e}", err=sys.stderr, fg=typer.colors.BRIGHT_MAGENTA)
        typer.Exit

def spf_validator(mechanism: str, validate: bool = True):
    if not validate:
        return True
    else:
        mechanism = mechanism.split(':')[0]
        for c in spf_modifiers:
            mechanism = mechanism.replace(c, '')
        if mechanism in spf_keywords:
            return True
        else:
            return False


def spftree(zone: str, indent: int = 0, validate: bool = True):
    """
    Create a tree structure of the zones SPF record
    """
    record = get_spf_from_zone(zone)

    # FIXME Combine records with multiple strings
    # It can possbily be n number of strings
    try:
        if len(record.strings) > 1:
            spf_record = record.strings[0] + record.strings[1]
        else:
            spf_record = record.strings[0]

        for field in spf_record.split():
            field = field.decode()
            if spf_validator(field, validate):
                typer.secho(' ' * indent + field, fg=typer.colors.GREEN)
            else:
                typer.secho(' ' * indent + field, fg=typer.colors.RED)
            if 'include:' in field:
                nextzone = field[field.index(':')+1:]
                spftree(nextzone, indent+2)
    except AttributeError as e:
        typer.secho(f"Error: {zone} {e}", err=sys.stderr, fg=typer.colors.BRIGHT_MAGENTA)


if __name__ == "__main__":
    typer.run(spftree)
