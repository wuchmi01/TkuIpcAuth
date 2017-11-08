using System;
using System.Web;

namespace TkuIpcAuth {
    public abstract class AuthStor: IDisposable {
        public abstract string GetAuthMethod();
        public abstract void SetAuthMethod(string authMethod);
        internal abstract TimeSpan GetRequestPrevTime();
        internal abstract void SetRequestCurrTime(TimeSpan currTime);
        internal abstract string GetUserID();
        internal abstract void SetUserID(string userID);        
        public abstract void Dispose();
    }
}
