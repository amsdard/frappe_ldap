import ldap, sys, frappe
from frappe.utils import nowdate,  nowtime, cstr
from frappe import sendmail
from templates.pages.ldap_login import upsert_profile, get_bound_connection
from frappe.utils import random_string
from frappe_ldap.templates.pages.ldap_login import get_ldap_settings
from frappe_ldap.ldap.doctype.ldap_settings.ldap_settings import set_ldap_connection


def check_profiles_daily():
    check_profiles_if("Daily")


def check_profiles_weekly():
    check_profiles_if("Weekly")


def check_profiles_monthly():
    check_profiles_if("Monthly")


def check_profiles_if(freq):
    if frappe.db.get_value("LDAP Settings", None, "sync_frequency")==freq:
        sync_ldap_users()


def sync_ldap_users():
    server_details = get_ldap_settings()
    conn = get_bound_connection(server_details)
    new_created = []

    for user in get_ldap_users(conn, server_details):
        result = upsert_profile()
        if result == "insert":
            new_created.append(user["mail"])

    # send email to admin about new users
    admin_notification(new_created)


def get_ldap_users(conn, server_details):
    users = []

    user_filter = server_details.get('user_filter', '')
    base_dn = server_details.get('base_dn')

    try:
        # search for erpnext users in ldap database
        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '${}'.format(user_filter))
    except ldap.LDAPError as e:
        frappe.msgprint("Incorrect Username or Password.", raise_exception=1)
        conn.unbind_s()
        raise

    for dn, r in result:
        users.append({
            "mail": str(r['mail'][0]),
            "username": str(r['cn'][0]),
            "first_name": str(r['givenName'][0]),
            "last_name": str(r['sn'][0]),
            "gidNumber":  str(r['gidNumber'][0])
        })

    return users


def admin_notification(new_profiels):
    msg = get_message(new_profiels)
    receiver = frappe.db.sql("select parent from tabUserRole where role = 'System Manager' and parent not like '%administrator%'", as_list=1)[0]
    
    if len(new_profiels) >= 1:
        frappe.sendmail(recipients=receiver, sender=None, subject="[LDAP-ERP] Newly Created Profiles", message=cstr(msg))


def get_message(new_profiels):
    return """ Hello Admin. \n
            Profiles has been synced. \n
            Please check the assigned roles to them. \n
            List is as follws:\n %s """%'\n'.join(new_profiels)
