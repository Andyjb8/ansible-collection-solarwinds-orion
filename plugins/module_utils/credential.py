# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# Orion.Credential.CredentialType markers for the credential set types this
# collection manages. Matched as a substring because the full type name is
# namespaced differently depending on which Orion component wrote the row
# (e.g. SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV3 alongside
# SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential).
CREDENTIAL_TYPE_MARKERS = {
    'snmpv3': 'SnmpCredentialsV3',
    'wmi': 'UsernamePasswordCredential',
}


class DuplicateCredentialError(Exception):
    """Raised when a credential set name does not identify exactly one set."""


def get_credentials(orion, name, credential_type=None):
    """Look up a credential set by name and (when given) credential type.

    A credential set name alone does not identify a single set: names may
    legitimately repeat across credential types, and Orion's duplicate-name
    check on create is not atomic, so concurrent creates of the same name can
    each create a set of the same type. Returning an arbitrary match is unsafe
    - the caller can bind a node to one set while updating another, and the
    match returned can differ between calls, since the query carries no
    ordering. Matches of a different credential_type are therefore ignored,
    and more than one match of the requested type is raised as
    DuplicateCredentialError rather than guessed at.
    """
    credential = {}
    query = f"""
    SELECT ID, Name, CredentialType
    FROM Orion.Credential
    WHERE Name = '{name}'
    """
    matches = orion.swis.query(query)['results']

    marker = CREDENTIAL_TYPE_MARKERS.get(credential_type)
    if marker:
        matches = [m for m in matches if marker in (m['CredentialType'] or '')]

    if len(matches) > 1:
        raise DuplicateCredentialError(
            "Credential set name '{0}' matches {1} credential sets of the same type ({2}), "
            "so the set to use is ambiguous - refusing to guess. Orion's duplicate-name "
            "check on create is not atomic, so concurrent runs against the same credential "
            "set name can each create one. Remove the unwanted sets (Settings > Manage "
            "Credentials) and re-run.".format(
                name,
                len(matches),
                ', '.join(
                    'ID {0} type {1}'.format(m['ID'], m['CredentialType']) for m in matches
                ),
            )
        )

    if matches:
        credential['ID'] = matches[0]['ID']
        credential['Name'] = matches[0]['Name']
        credential['CredentialType'] = matches[0]['CredentialType']
    return credential


def create_snmpv3_credentials(orion, name, snmp3_props: dict, context: str = '', owner: str = 'Orion'):
    result = orion.swis.invoke(
        'Orion.Credential', 'CreateSNMPv3Credentials', name, snmp3_props['username'], context,
        snmp3_props['auth_method'], snmp3_props['auth_key'], snmp3_props['auth_key_is_pwd'],
        snmp3_props['priv_method'], snmp3_props['priv_key'], snmp3_props['priv_key_is_pwd'],
        owner)
    return result


def create_username_password_credentials(orion, name, wmiProps: dict, owner):
    result = orion.swis.invoke('Orion.Credential', 'CreateUsernamePasswordCredentials', name, wmiProps['username'], wmiProps['password'], owner)
    return result


def validate_snmp3_credentials(orion, node, properties, port: int = 161):
    snmp3_credentials = {
        'UserName': properties['username'],
        'Context': '',
        'PrivacyType': properties['priv_method'],
        'PrivacyPassword': properties['priv_key'],
        'PrivacyKeyIsPassword': properties['priv_key_is_pwd'],
        'AuthenticationPassword': properties['auth_key'],
        'AuthenticationType': properties['auth_method'],
        'AuthenticationKeyIsPassword': properties['auth_key_is_pwd'],
    }
    result = orion.swis.invoke(
        'Orion.Discovery',
        'ValidateCredentials',
        node['ipaddress'],
        port,
        'SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV3',
        snmp3_credentials,
        node['engineid'],
    )
    return result


def assign_credentials_to_node(orion, node, credentialSet, nodeSetting):
    properties = {
        'NodeID': node['nodeid'],
        'SettingName': nodeSetting,
        'SettingValue': credentialSet['ID']
    }
    result = orion.swis.create(
        'Orion.NodeSettings',
        **properties
    )
    return result
