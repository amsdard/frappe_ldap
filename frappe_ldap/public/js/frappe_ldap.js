/**
 * Created by koszi on 13.10.2016.
 */

$("#ldap-login").unbind("click");
$("#ldap-login").on("click", function(event) {
    event.preventDefault();

    var args = {};
    args.cmd = "ldap_login";
    args.user = ($("#login_email").val() || "").trim();
    args.pwd = $("#login_password").val();
    args.device = "desktop";
    if(!args.user || !args.pwd) {
        frappe.msgprint(__("Both login and password required"));
        return false;
    }

    frappe.call({
        method: "frappe_ldap.templates.pages.ldap_login.ldap_login",
		type: "POST",
		args: args,
		freeze: true,
		statusCode: login.login_handlers
	});

    //login.call(args);
    return false;
});

$(".form-signin").unbind("submit");
$(".form-signin").on("submit", function(event){
    event.preventDefault();
    $("#ldap-login").click();
});