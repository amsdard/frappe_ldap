from __future__ import unicode_literals
import json
import ldap
import itertools
import frappe
import frappe.utils
from frappe import _
from frappe.utils import nowdate, nowtime, cint
from frappe.defaults import set_default, clear_cache
from frappe.utils.password import get_decrypted_password, get_encryption_key
from frappe_ldap.ldap.doctype.ldap_settings.ldap_settings import set_ldap_connection


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
    conn = get_bound_connection(server_details)

    # get user
    user = get_ldap_user(conn, username, pwd, server_details)

    # get groups
    groups = get_ldap_groups(conn, user, server_details)

    # update erpnext
    upsert_profile(user, pwd, groups)

    return user


def get_bound_connection(server_details):
    """Get ldap connection and bind readonly user."""

    conn = set_ldap_connection(server_details)
    user_dn = server_details.get('user_dn')
    password = get_decrypted_password("LDAP Settings", "LDAP Settings", "pwd")

    try:
        # bind with ldap readonly user
        conn.simple_bind_s(user_dn, password)
    except ldap.LDAPError as e:
        frappe.msgprint("Incorrect Ldap Settings", raise_exception=1)
        conn.unbind_s()
        raise

    return conn


def get_ldap_user(conn, username, pwd, server_details):
    user = None

    user_filter = server_details.get('user_filter', '')
    user_dn = None
    base_dn = server_details.get('base_dn')

    try:
        # search for erpnext user in ldap database
        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(&(uid={}){})'.format(username, user_filter))
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
            user_conn = set_ldap_connection(server_details)
            user_conn.simple_bind_s(user_dn, pwd)
        except ldap.LDAPError as e:
            frappe.msgprint("Incorrect Username or Password", raise_exception=1)
            raise
        finally:
            user_conn.unbind_s()
    else:
        frappe.msgprint("Not a valid LDAP user", raise_exception=1)

    return user


def get_ldap_groups(conn, user, server_details):
    """ Return names of all posixGroups to which user belongs."""

    base_dn = server_details.get('base_dn')
    result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(&(objectClass=posixGroup)(memberUid={}))'.format(user['username']))

    groups = []
    for dn, r in result:
        groups.append(r['cn'][0])

    return groups


def upsert_profile(user, pwd, groups):
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
    update_roles(user, get_role_list(groups))
    update_user_permissions(user, groups)

    return result


def update_roles(user, roles):
    user = frappe.get_doc("User", user['mail'])
    current_roles = [d.role for d in user.get("user_roles") if d.owner=="ldap" ]

    user.remove_roles(*list(set(current_roles) - set(roles)))
    user.add_roles(*roles)

    for role in roles:
        # change new roles ownership to ldap
        frappe.db.sql("update tabUserRole set owner='ldap' where parent='%s' and role='%s'" % (user.email, role))


def update_user_permissions(user, groups):
    """Sets projects permission based on ldap posix groups"""

    current_permissions = itertools.chain(
        *(frappe.db.sql("SELECT defvalue FROM tabDefaultValue WHERE owner='ldap' "
                        "AND parent='%s' AND parenttype='User Permission' AND defkey='Project'" % (user['mail']))))

    not_existing_permissions = list(set(current_permissions) - set(groups))
    new_permissions = list(set(groups) - set(current_permissions))

    # delete not existing project permissions
    if not_existing_permissions:
        frappe.db.sql("DELETE FROM tabDefaultValue WHERE parent='%s' AND parenttype='User Permission' "
                      "AND defkey='Project' AND owner='ldap' AND defvalue IN (%s) "
                      % (user['mail'], ','.join("'%s'" % p for p in not_existing_permissions)))

    if new_permissions:
        for name in new_permissions:
            d = frappe.get_doc({
                "owner": "ldap",
                "doctype": "DefaultValue",
                "parent": user['mail'],
                "parenttype": "User Permission",
                "parentfield": "system_defaults",
                "defkey": 'Project',
                "defvalue": name
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
