using System.Web;

namespace TkuIpcAuth {
    public class AuthStorFactory {
        AuthStor authStor;

        /// <summary>
        /// 取得 AuthStor 物件
        /// </summary>
        /// <param name="context">目前正在使用的 HttpContext</param>
        /// <param name="storName">欲使用的儲存機制</param>
        /// <returns></returns>
        public AuthStor GetAuthStor(HttpContextBase context, string storName) { 
            switch (storName.ToLower()) { 
                case "web":
                    authStor = new WebAuthStor(context);
                    break;

                default:
                    break;
            }

            return authStor;
        }

        /// <summary>
        /// 取得 AuthStor 物件
        /// </summary>
        /// <param name="context">目前正在使用的 HttpContext</param>
        /// <param name="storName">欲使用的儲存機制</param>
        /// <param name="authName">設定目前User使用的驗證機制 (一旦設定後，儲存機制立馬啟動 ex: Session)</param>
        /// <returns></returns>
        public AuthStor GetAuthStor(HttpContextBase context, string storName, string authName) {
            var authStor = GetAuthStor(context, storName);
            authStor.SetAuthMethod(authName);

            return authStor;
        }
    }
}
