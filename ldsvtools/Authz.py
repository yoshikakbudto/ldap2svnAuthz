#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Do funny stuff with authz."""

import pprint
import sys
from Config import CONFIG, AUTHZ

try:
    import ldap3
    from ldap3 import Server, Connection, ALL
except ImportError:
    print('[ERROR] Unable to locate the "ldap3" module. '
          'Please install with "pip install ldap3" (https://github.com/cannatag/ldap3)')
    sys.exit(1)

def load():
    """Loads yaml config access to internal structure."""
    server = Server(CONFIG['ldap']['url'], get_info=ALL)
    try:
        conn = Connection(server, CONFIG['ldap']['bind_dn'], CONFIG['ldap']['bind_pw'],
                          auto_bind=True, check_names=False, auto_encode=True)
    except (ldap3.core.exceptions.LDAPSocketOpenError,
            ldap3.core.exceptions.LDAPBindError), error_message:
        print("[ERROR] failed to bind to '%s' with dn: %s\ninternal error: %s" %
              (CONFIG['ldap']['url'], CONFIG['ldap']['bind_dn'], error_message))

        sys.exit(1)

    AUTHZ['access']['*'] = CONFIG['svn']['default_everyone_perms']

    for obj, objparams in CONFIG['svn']['access'].iteritems():
        if CONFIG['debug']:
            print("[DEBUG] Getting svn-accesses for %s" % obj)

        if obj == 'DEFAULT_GROUP':
            group_name = CONFIG['svn']['default_groupname_pfx'] + CONFIG['svn']['repo_name']
            try:
                perms = objparams
            except NameError:
                if CONFIG['debug']:
                    print("[DEBUG] using default value (%s) for %s"
                          % (CONFIG['svn']['default_perms'], group_name))
                perms = CONFIG['svn']['default_perms']
            store_group_access(conn, perms, group_name)

        elif obj in ['EVERYONE', 'ANYONE', 'ANYBODY', 'EVERYBODY', 'ALL', 'ANY', 'DEFAULT', '*']:
            try:
                perms = objparams
            except NameError:
                if CONFIG['debug']:
                    print("[DEBUG] using default value (%s) for '*'"
                          % CONFIG['svn']['default_everyone_perms'])
                perms = CONFIG['svn']['default_everyone_perms']

            AUTHZ['access']['*'] = perms

        else:
            if not isinstance(objparams, dict):
                print("[ERROR] '%s' should be either a predefined clause or has "
                      "a dictionary values like 'type' and 'perms', given: '%s'"
                      % (obj, objparams))
                sys.exit(1)

            if 'type' not in objparams:
                print("[ERROR] '%s' has no type and perms set. Given: '%s' "
                      % (obj, objparams))
                sys.exit(1)

            try:
                perms = objparams['perms']
            except KeyError:
                if CONFIG['debug']:
                    print("[DEBUG] using default value (%s) for %s"
                          % (CONFIG['svn']['default_perms'], obj))
                perms = CONFIG['svn']['default_perms']

            if objparams['type'] == 'group':
                group_name = obj
                store_group_access(conn, perms, group_name)
            elif objparams['type'] == 'user':
                AUTHZ['access'][obj] = perms
            else:
                print("[ERROR] unsupported object type (%s) in %s "
                      % (objparams['type'], obj))

    if CONFIG['debug']:
        pprint.pprint(AUTHZ)


def store_group_access(conn, perms, group_name):
    """Update AUTHZ dict with group accesses and members."""

    AUTHZ['access']['@'+group_name] = perms

    r = get_members(conn, group_name)
    # store group name even if it has not any users.
    AUTHZ['groups'][group_name] = r['users']

    if CONFIG['ldap']['group_traversal'] and r['groups']:
        for subgroup in r['groups']:
            # perm are enherited from above
            AUTHZ['access']['@'+group_name+'_'+subgroup] = perms
            r = get_members(conn, subgroup)
            AUTHZ['groups'][group_name+'_'+subgroup] = r['users']


def get_members(conn, group):
    """Return dict of users and groups lists."""
    result = {'users': [], 'groups': []}

    conn.search(CONFIG['ldap']['search_dn'],
                "(&(objectclass=group)(cn=%s))" % group,
                attributes=['member'])
    try:
        if len(conn.entries[0]['member']) == 0:
            print("[WARN] the group %s has no members :(" % group)
    except IndexError:
        print("[ERROR] the group '%s' was not found in LDAP. And no custom config found" % group)
        sys.exit(1)

    for cn in conn.entries[0]['member']:
        # collect user members by filter
        conn.search(cn, CONFIG['ldap']['user_query'],
                    attributes=[CONFIG['ldap']['objid_attribute']])
        try:
            result['users'] += conn.entries[0][CONFIG['ldap']['objid_attribute']]
        except IndexError:
            if CONFIG['debug']:
                print("%s didnt pass the USER filter" % cn)

        # collect group members if needed
        if CONFIG['ldap']['group_traversal']:
            conn.search(cn, '(objectclass=group)', attributes=['cn'])
            try:
                result['groups'] += conn.entries[0]['cn']
            except IndexError:
                if CONFIG['debug']:
                    print("%s didnt pass the GROUP filter" % cn)
    return result

def save():
    """authz_paths authz to file or STDOUT."""

    authz_content = CONFIG['svn']['authz_header']
    authz_content += "\n[groups]"

    for group, members in AUTHZ['groups'].iteritems():
        authz_content += '\n' + group + ' = ' + ', '.join(members)

    authz_content += '\n\n[/]'

    for obj, perm in AUTHZ['access'].iteritems():
        if not obj == '*':
            authz_content += '\n' + obj + ' = ' + perm

    authz_content += '\n* = ' + AUTHZ['access']['*']
    authz_content += CONFIG['svn']['authz_footer']

    if CONFIG['svn']['authz_path']:
        authz_path = CONFIG['svn']['authz_path']
    else:
        authz_path = CONFIG['svn']['repos_root'] + '/' + CONFIG['svn']['repo_name'] + '/conf/authz'

    if CONFIG['dry_run']:
        print("---\n--- The content of %s would be: " % authz_path)
        print authz_content
    else:
        print("[INFO] re-writing %s" % authz_path)
        with open(authz_path, 'w') as output:
            output.write(authz_content.encode('utf-8'))
