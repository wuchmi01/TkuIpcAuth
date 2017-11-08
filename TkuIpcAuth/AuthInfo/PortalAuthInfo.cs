using System.Web;
using System.Web.Security;

namespace TkuIpcAuth {
    public class PortalAuthInfo : AuthInfo {
        private string sso_userid = null;

        private void init() {
            stor.SetAuthMethod("portal");

            sso_userid = context.Request.Headers["sso_userid"];
        }

        public PortalAuthInfo(HttpContext context, AuthStor stor) : base(context, stor) {
            init();
        }

        public PortalAuthInfo(HttpContextBase context, AuthStor stor) : base(context, stor) { 
            init();
        }

        public override string GetUserID() {
            return sso_userid;
        }

        public override bool IsAuthenticated() {            
            return !string.IsNullOrEmpty(sso_userid);
        }

        public override void SignIn(string userID) {
            // do nothing
        }

        public override void SignOut() {            
            stor.Dispose();
        }

        public override string RedirectToLoginUrl() {
            throw new System.NotImplementedException();
        }
    }
}
