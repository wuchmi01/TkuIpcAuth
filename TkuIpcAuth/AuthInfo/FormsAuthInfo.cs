using System.Web;
using System.Web.Security;

namespace TkuIpcAuth {
    public class FormsAuthInfo : AuthInfo {
        private void init() {
            stor.SetAuthMethod("forms");
        }

        public FormsAuthInfo(HttpContext context, AuthStor stor) : base(context, stor) {
            init();
        }

        public FormsAuthInfo(HttpContextBase context, AuthStor stor) : base(context, stor) { 
            init();
        }

        public override string GetUserID() {
            return stor.GetUserID();
        }

        public override bool IsAuthenticated() {
            return context.Request.IsAuthenticated;
        }

        public override void SignIn(string userID) {
            stor.SetUserID(userID);            
        }

        public override void SignOut() {            
            stor.Dispose();
        }

        public override string RedirectToLoginUrl() {
            throw new System.NotImplementedException();
        }
    }
}
