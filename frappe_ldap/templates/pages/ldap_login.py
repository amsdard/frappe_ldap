from __future__ import unicode_literals
import json
import ldap
import os
import itertools
import frappe
import frappe.utils
from frappe import _
from frappe.utils import nowdate, nowtime, cint
from frappe.defaults import set_default, clear_cache
from ldapsync2 import LdapSyncUtils


env = os.environ.get
SERVER = env('LDAP_SERVER')
PORT = env("LDAP_PORT") or '636'
CA_PATH = env("LDAP_CA_PATH")

BIND_DN = env('LDAP_BIND_DN')
BIND_PASSWORD = env('LDAP_BIND_PASSWORD')

USER_SEARCH_BASE = env('LDAP_USER_DN')
USER_SEARCH_FILTER = env('LDAP_USER_FILTER')

GROUP_SEARCH_BASE = env('LDAP_GROUP_DN')
GROUP_SEARCH_FILTER = env('LDAP_GROUP_FILTER')
GROUP_SEARCH_SUBTREES = env('GROUP_SEARCH_SUBTREES', 'clients,projects,products')
GROUP_SUBTREES = ['{},{}'.format(t, GROUP_SEARCH_BASE) for t in GROUP_SEARCH_SUBTREES.split(',')]


@frappe.whitelist(allow_guest=True)
def ldap_login(user, pwd, provider=None):
    """ Ldap login controller. Tries to authenticate with ldap database, redirects to desktop on success. """
    username = user

    # make session user as Admin to create share doc entry
    frappe.session.user = 'Administrator'

    user = ldap_authentication(username, pwd)

    frappe.local.login_manager.user = user['mail']
    frappe.local.login_manager.post_login()

    return "Logged In"


def ldap_authentication(username, pwd):
    server_details = get_ldap_settings()

    # get connection
    utils = LdapSyncUtils()

    # get user
    user = get_ldap_user(utils.conn, username, pwd)

    # get groups
    groups = utils.get_user_ldap_groups(username)
    roles = utils._get_posix_groups(username, scope=1, only_subtrees=False)

    # update erpnext
    user['username'] = user['username'].replace('.', '_')
    upsert_profile(user, pwd, groups, roles)

    return user


def get_ldap_user(conn, username, pwd):
    user = None
    user_dn = None

    try:
        # search for erpnext user in ldap database
        result = conn.search_s(
            USER_SEARCH_BASE,
            ldap.SCOPE_SUBTREE,
            '(&(uid={}){})'.format(username, USER_SEARCH_FILTER),
            [ str('cn'), str('entryDN'), str('mail'), str('givenName'), str('gidNumber'), str('sn')]

        )
    except ldap.LDAPError as e:
        frappe.msgprint("Incorrect Username or Password.", raise_exception=1)
        conn.unbind_s()
        raise

    for dn, r in result:
        user_dn = str(dn)
        user = {
            "mail": str(r['mail'][0]),
            "username": username,
            "first_name": str(r['givenName'][0]),
            "last_name": str(r['sn'][0]),
            "gidNumber":  str(r['gidNumber'][0])
        }

    # check if provided user password is correct
    if user_dn:
        try:
            utils = LdapSyncUtils()
            utils.get_connection(user_dn, pwd)
        except ldap.LDAPError as e:
            frappe.msgprint("Incorrect Username or Password", raise_exception=1)
            raise
        finally:
            utils.conn.unbind_s()
    else:
        frappe.msgprint("Not a valid LDAP user", raise_exception=1)

    return user


def upsert_profile(user, pwd, groups, roles):
    """ Creates or updates user profile. """
    result = None
    profile = frappe.db.sql("select name from tabUser where username = '%s'" % user['username'])
    if not profile:
        d = frappe.new_doc("User")
        d.owner = "Administrator"
        d.email = user['mail']
        d.username = user['username']
        d.first_name = user['first_name']
        d.last_name = user['last_name']
        d.enabled = 1
        d.new_password = pwd
        d.creation = nowdate() + ' ' + nowtime()
        d.user_type = "System User"
        d.save(ignore_permissions=True)
        result = "insert"
    else:
        frappe.db.sql("update tabUser set email='%s', first_name='%s', last_name='%s' where username='%s'" %
                      (user['mail'], user['first_name'], user['last_name'], user['username']))
        result = "update"

    # update user's roles, as they might have changed from last login
    update_roles(user, get_role_list(roles))
    update_user_permissions(user, groups)

    return result


def update_roles(user, roles):
    user = frappe.get_doc("User", user['mail'])
    user_roles = user.get("roles") or []
    current_roles = [d.role for d in user_roles if d.owner=="ldap" ]

    user.remove_roles(*list(set(current_roles) - set(roles)))
    user.add_roles(*roles)

    for role in roles:
        # change new roles ownership to ldap
        frappe.db.sql("update `tabHas Role` set owner='ldap' where parent='%s' and role='%s'" % (user.email, role))


def update_user_permissions(user, groups):
    """Sets projects permission based on ldap posix groups"""

    current_permissions = list(itertools.chain.from_iterable(
        (frappe.db.sql("SELECT for_value FROM `tabUser Permission` WHERE owner='ldap' "
                        "AND user='%s' AND allow='Project'" % (user['mail'])))))

    not_existing_permissions = list(set(current_permissions) - set(groups))
    new_permissions = list(set(groups) - set(current_permissions))

    # delete not existing project permissions
    if not_existing_permissions:
        frappe.db.sql("DELETE FROM `tabUser Permission` WHERE user='%s' AND allow='Project' "
                      " AND for_value IN (%s) "
                      % (user['mail'], ','.join("'%s'" % p for p in not_existing_permissions)))

    if new_permissions:
        for name in new_permissions:
            d = frappe.get_doc({
                "owner": "ldap",
                "doctype": "User Permission",
                "user": user['mail'],
                "allow": "Project",
                "for_value": name,
                "apply_for_all_roles": 0
            })

            d.insert(ignore_permissions=True)

    clear_cache(user['mail'])


def get_role_list(groups):
    """ Map ldap groups to erpnext roles using matched mapper."""
    role_list = []
    for group in groups:
        role_list.extend(frappe.db.sql("select role from `tabRole Mapper Details` where parent='%s'" % (group), as_list=1))
    return list(itertools.chain(*role_list))


def get_ldap_settings():
    return frappe.db.get_value("LDAP Settings", None,
                               ['ldap_server','user_dn','base_dn', 'tls_ca_path', 'user_filter', 'project_filter', 'pwd'], as_dict=1)
