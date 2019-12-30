using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace DiarioSDKNet
{
    public class ApiResponse
    {
        public Dictionary<string, object> Data
        {
            get;
            private set;
        }
        public Error Error
        {
            get;
            private set;
        }

        private static JavaScriptSerializer js = new JavaScriptSerializer();

        public ApiResponse(String json)
        {
            Dictionary<string, object> response = (Dictionary<string, object>)js.DeserializeObject(json);
            if (response.ContainsKey("data"))
            {
                this.Data = (Dictionary<string, object>)response["data"];
            }

            if (response.ContainsKey("error"))
            {
                Dictionary<string, object> err = (Dictionary<string, object>)response["error"];
                int code;
                if (err.ContainsKey("code") && int.TryParse(err["code"].ToString(), out code))
                {
                    String message = err.ContainsKey("message") ? err["message"].ToString() : string.Empty;
                    this.Error = new Error(code, message);
                }
            }
        }
    }
}
