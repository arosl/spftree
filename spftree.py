#!/usr/bin/env python3
import typer
import sys
import dns.resolver
from typing import Optional

spf_keywords = ['all', 'a', 'ip4', 'ip6', 'mx', 'ptr', 'exists', 'include', 'redirect', 'v=spf1', '"v=spf1']
spf_modifiers = ['+', '-', '~', '?']

def get_spf_from_zone(zone: str, timeout: float = 1.0) -> Optional[dns.resolver.Answer]:
    """
    Get SPF record from zone by checking if the TXT record contains
    valid spf keywords or mechanisms.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '1.0.0.1']
        spf = resolver.resolve(zone, 'TXT', raise_on_no_answer=False)
        for record in spf:
            if str(record).split()[0] in spf_keywords:
                return record
    except Exception as e:
        typer.secho(f"Error: {zone} {e}", err=sys.stderr, fg=typer.colors.BRIGHT_MAGENTA)
        typer.Exit()

def spf_validator(mechanism: str, validate: bool = True) -> bool:
    """
    Validate an SPF mechanism.
    """
    if not validate:
        return True
    else:
        mechanism = mechanism.split(':')[0]
        mechanism = ''.join([c for c in mechanism if c not in spf_modifiers])
        return mechanism in spf_keywords

def spftree(zone: str, indent: int = 0, validate: bool = True) -> None:
    """
    Create a tree structure of the zone's SPF record.
    """
    record = get_spf_from_zone(zone)

    try:
        spf_record = b''.join(record.strings).decode()
        for field in spf_record.split():
            if spf_validator(field, validate):
                typer.secho(f"{' ' * indent}{field}", fg=typer.colors.GREEN)
            else:
                typer.secho(f"{' ' * indent}{field}", fg=typer.colors.RED)
            if 'include:' in field:
                nextzone = field.split(':')[1]
                spftree(nextzone, indent+2)
    except AttributeError as e:
        typer.secho(f"Error: {zone} {e}", err=sys.stderr, fg=typer.colors.BRIGHT_MAGENTA)

if __name__ == "__main__":
    typer.run(spftree)
