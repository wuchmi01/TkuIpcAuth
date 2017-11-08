using System;
using System.Security.Principal;
using System.Web;
using System.Web.Security;

namespace TkuIpcAuth {
    public class WebAuthStor: AuthStor {
        string _ss_auth_nm   = "_MY_AUTH_NM",
               _ss_requst_tm = "_MY_REQUEST_TIME";

        HttpContextBase context;
        
        public WebAuthStor(HttpContextBase context) { 
            this.context = context;
        }        

        public override string GetAuthMethod() {
            var method = (context.Session[_ss_auth_nm] ?? string.Empty).ToString();
            return method;
        }

        public override void SetAuthMethod(string authMethod) {
            context.Session[_ss_auth_nm] = authMethod;
        }
        
        internal override TimeSpan GetRequestPrevTime() {
            var time = (TimeSpan)context.Session[_ss_requst_tm];            
            return time;
        }

        internal override void SetRequestCurrTime(TimeSpan currTime) {
            context.Session[_ss_requst_tm] = currTime;
        }

        internal override string GetUserID() {
            return context.User.Identity.Name;
        }

        internal override void SetUserID(string userID) {
            FormsAuthentication.SetAuthCookie(userID, false);
            
            //renew ticket
            var cookie = context.Request.Cookies[FormsAuthentication.FormsCookieName];
            var ticket = FormsAuthentication.Decrypt(cookie.Value);

            context.User = new GenericPrincipal(new FormsIdentity(ticket), null);
        }
        
        public override void Dispose() {
            FormsAuthentication.SignOut();
            context.Session.Clear();
        }
    }
}
