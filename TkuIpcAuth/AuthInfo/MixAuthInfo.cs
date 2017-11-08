using System.Web;
using System.Web.Security;

namespace TkuIpcAuth {
    public class MixAuthInfo : AuthInfo {
        private void init() {
            this.stor.SetAuthMethod("mix");
        }

        public MixAuthInfo(HttpContext context, AuthStor stor) : base(context, stor) {
            init();
        }

        public MixAuthInfo(HttpContextBase context, AuthStor stor) : base(context, stor) { 
            init();
        }

        public override string GetUserID() {            
            var request = context.Request;

            // 從 stor 取得。若無，則自 Requset.QueryString 取得。若仍無，則自 Request.Header 取得。
            string uid  = stor.GetUserID();

            if (string.IsNullOrEmpty(uid)) { 
                uid = request["uid"] ?? request.Headers["sso_userid"];
            }

            return uid;
        }

        public override bool IsAuthenticated() {
            string uid  = stor.GetUserID();
            bool isAuth = !string.IsNullOrEmpty(uid);

            if (!isAuth) { 
                var request = context.Request;

                uid    = request["uid"];
                isAuth = !string.IsNullOrEmpty(uid);
                
                if (!isAuth) { 
                    uid    = request["sso_userid"];
                    isAuth = !string.IsNullOrEmpty(uid);
                }
                else { 
                    stor.SetUserID(uid);
                }
            }

            return isAuth;
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
