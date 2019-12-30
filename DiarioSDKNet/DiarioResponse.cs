using System.Collections.Generic;
using Newtonsoft.Json;

namespace DiarioSDKNet
{
    public class DiarioResponse<T>
    {
        public Dictionary<string, T> Data { get; set; }

        public Error Error { get; set; }

        public DiarioResponse()
        {
        }

        public DiarioResponse(string json)
        {
            var response = JsonConvert.DeserializeObject<DiarioResponse<T>>(json);

            Data = response.Data;
            Error = response.Error;
        }
    }
}
