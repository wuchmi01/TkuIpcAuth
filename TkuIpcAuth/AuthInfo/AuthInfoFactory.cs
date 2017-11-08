using System.Web;

namespace TkuIpcAuth {
    public class AuthInfoFactory {
        AuthInfo authInfo;

        public AuthInfo GetAuthInfo(HttpContextBase context, AuthStor stor) { 
            string method = stor.GetAuthMethod();

            switch (method) { 
                case "forms":
                    authInfo = new FormsAuthInfo(context, stor);
                    break;

                case "mix":
                    authInfo = new MixAuthInfo(context, stor);
                    break;

                case "portal":
                    authInfo = new PortalAuthInfo(context, stor);
                    break;

                default:
                    authInfo = new FormsAuthInfo(context, stor);
                    break;
            }

            return authInfo;
        }
    }
}
