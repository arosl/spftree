#!/usr/bin/env python3
import typer
import sys
import dns.resolver

spf_mechanisms = ['all', 'a', 'ip4', 'ip6', 'mx',
                  'ptr', 'exists', 'include', 'v=spf1']
spf_modifiers = ['+', '-', '~', '?']

spf_keywords = spf_mechanisms
for i in range(len(spf_mechanisms)):
    for j in range(len(spf_modifiers)):
        spf_keywords.append(f'{spf_modifiers[j]}{spf_mechanisms[i]}')

spftree_model = []
dns_counter = 0


def get_spf_from_zone(zone: str, timeout: float = 1.0):
    """
    Get SPF record from zone by checking if the TXT record starts 
    as valid SPF with exactly "v=spf1".
    """
    global dns_counter
    dns_counter += 1
    try:
        # FIXME get to many timeouts for now, always after 5.4 sec.
        # setting resolver.timeout = timeout does not change the timeout.
        resolver = dns.resolver
        spf = resolver.resolve(zone, 'TXT', raise_on_no_answer=False)
        for record in spf:
            if str(record).split()[0] == '"v=spf1':
                return record
    except Exception as e:
        typer.secho(f"Error: {zone} {e}", err=sys.stderr,
                    fg=typer.colors.BRIGHT_MAGENTA)
        typer.Exit


def spf_validator(mechanism: str, validate: bool = True):
    """
    Validate if a mechanism is a known SPF mecanism or not.
    If the validate param is set to false always return True.
    """
    if not validate:
        return True
    else:
        mechanism = mechanism.split(':')[0]
        if mechanism in spf_keywords:
            return True
        if mechanism.split('=')[0] == 'redirect':
            return True
        else:
            return False


def get_spf_fields(zone: str):
    """
    Split a spf record down to it's individual fields.
    Return a list with fields.
    """
    fields = []
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
            fields.append(field)
        return fields

    except AttributeError as e:
        typer.secho(f"Error: {zone} {e}", err=sys.stderr,
                    fg=typer.colors.BRIGHT_MAGENTA)


def get_spftree(fields: list, indent: int = 0):
    """
    Create a model of a tree structure of the SPF record
    """
    try:
        for field in fields:
            field_model = {
                'field': field,
                'valid': spf_validator(field),
                'indent_level': indent
            }
            spftree_model.append(field_model)
            if 'include:' in field:
                # select the url after include and get the fields
                nextzone = get_spf_fields(field.split(':')[1])
                get_spftree(nextzone, indent+1)

        return spftree_model
    except Exception as e:
        typer.secho(f"Error: {e}", err=sys.stderr,
                    fg=typer.colors.BRIGHT_MAGENTA)


def print_spftree(spftree_model: list, validate: bool = True, indent: int = 2):
    for item in spftree_model:
        if validate and item.get('valid'):
            typer.secho(' ' * (indent * item.get('indent_level')) +
                        item.get('field'), fg=typer.colors.GREEN)
        if validate and not item.get('valid'):
            typer.secho(' ' * (indent * item.get('indent_level')) +
                        item.get('field'), fg=typer.colors.RED)
        if not validate:
            typer.echo(' ' * (indent * item.get('indent_level')) +
                       item.get('field'))
    typer.echo('')


def print_dnscount(dns_counter: int, validate: bool = True):
    if validate and dns_counter <= 10:
        typer.secho(f'DNS lookup is OK! \n{dns_counter} lookups is valid RFC 7208 4.6.4',
                    fg=typer.colors.GREEN)
    if validate and dns_counter > 10:
        typer.secho(f'DNS lookup is not OK! \n{dns_counter} lookups breaks RFC 7208 4.6.4',
                    fg=typer.colors.RED)
    if not validate:
        typer.echo(f'DNS lookups done {dns_counter} times.')


def main(zone: str, indent: int = 4, validate: bool = True):
    fields = get_spf_fields(zone)
    spftree = get_spftree(fields)
    print_spftree(spftree, validate, indent)
    print_dnscount(dns_counter, validate)


if __name__ == "__main__":
    typer.run(main)
