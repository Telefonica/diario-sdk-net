using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace DiarioSDKNet
{

    public enum HttpVerbs
    {
        Get,
        Post,
        Put,
        Delete

    }

    public abstract class BaseSdk
    {
        protected const char AuthorizationHeaderFieldSeparator = ' ';
        protected const char ParamSeparator = '&';
        protected const char ParamValueSeparator = '=';
        protected const char X11PathsHeaderSeparator = ':';
        protected const string AuthorizationMethod = "11PATHS";
        protected const string QueryStringDelmiter = "?";
        protected const string UtcStringFormat = "yyyy-MM-dd HH:mm:ss";
        protected const string X11PathsHeaderPrefix = "X-11paths-";
        public const string AuthorizationHeaderName = "Authorization";
        public const string BodyHashHeaderName = X11PathsHeaderPrefix + "Body-Hash";
        public const string DateHeaderName = "X-11Paths-Date";
        public const string DateName = "Date";
        public const string FileHashHeaderName = X11PathsHeaderPrefix + "File-Hash";
        public const string HttpHeaderContentTypeFormUrlencoded = "application/x-www-form-urlencoded";
        public const string HttpHeaderContentTypeJson = "application/json";
        public const string MultiPartFormData = "multipart/form-data";

        private ConfigurationProxy proxy;

        public ConfigurationProxy Proxy
        {
            get
            {
                return proxy;
            }
            private set
            {
                proxy = value;
            }
        }

        private enum HeaderPart { Signature = 0, AppId = 1, AuthMethod = 2 };

        protected string AppId { get; private set; }
        protected string SecretKey { get; private set; }

        /// <summary>
        /// Creates an instance of the class with the <code>Application ID</code> and <code>Secret</code> obtained from Eleven Paths
        /// </summary>
        protected BaseSdk(string appId, string secretKey)
        {
            this.AppId = appId;
            this.SecretKey = secretKey;
        }

        public void SetProxyConfiguration(string host, int port, string user, string password, string domain)
        {
            if (Proxy == null)
            {
                Proxy = new ConfigurationProxy();
            }

            try
            {
                Proxy.SetHost(host)
                .SetPort(port)
                .SetUser(user)
                .SetPassword(password)
                .SetDomain(domain);
            }
            catch (ArgumentException e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
            }
        }

        protected DiarioResponse<T> HttpGetProxy<T>(string url, IDictionary<string, string> queryParams)
        {
            try
            {
                url = String.Concat(url, ParseQueryParams(queryParams));
                return HttpGet<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithParams(HttpVerbs.Get, url, null, null));
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        private DiarioResponse<T> HttpGet<T>(string url, IDictionary<string, string> headers)
        {
            return Http<T>(new Uri(url), HttpVerbs.Get, headers, null);
        }

        protected DiarioResponse<T> HttpDeleteProxy<T>(string url)
        {
            try
            {
                return HttpDelete<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithParams(HttpVerbs.Delete, url, null, null));
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        private DiarioResponse<T> HttpDelete<T>(string url, IDictionary<string, string> headers)
        {
            return Http<T>(new Uri(url), HttpVerbs.Delete, headers, null);
        }

        protected DiarioResponse<T> HttpPostProxy<T>(string url, IDictionary<string, string> data)
        {
            try
            {
                return HttpPost<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithParams(HttpVerbs.Post, url, null, data), data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        protected DiarioResponse<T> HttpPostProxy<T>(string url, string body)
        {
            try
            {
                return HttpPost<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithBody(HttpVerbs.Post, url, null, body), body);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        protected DiarioResponse<T> HttpPostFileProxy<T>(string url, HttpPostedFileBase file, byte[] fileBytes, string filename, IDictionary<string, string> xHeaders = null)
        {
            try
            {
                var headers = AuthenticationHeadersWithFile(HttpVerbs.Post, url, xHeaders, fileBytes);

                if (xHeaders != null)
                {
                    foreach (var header in xHeaders)
                    {
                        if (!headers.ContainsKey(header.Key))
                        {
                            headers.Add(header.Key, header.Value);
                        }
                    }
                }

                return HttpPostFile<T>(String.Concat(GetApiHost(), url), headers, file, fileBytes, filename);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        private DiarioResponse<T> HttpPost<T>(string url, IDictionary<string, string> headers, IDictionary<string, string> data)
        {
            return Http<T>(new Uri(url), HttpVerbs.Post, headers, data);
        }

        private DiarioResponse<T> HttpPost<T>(string url, IDictionary<string, string> headers, string body)
        {
            return Http<T>(new Uri(url), HttpVerbs.Post, headers, body, null, null, null, HttpHeaderContentTypeJson);
        }

        private DiarioResponse<T> HttpPostFile<T>(string url, IDictionary<string, string> headers, HttpPostedFileBase file, byte[] fileBytes, string filename)
        {
            return Http<T>(new Uri(url), HttpVerbs.Post, headers, null, file, fileBytes, filename, MultiPartFormData);
        }

        protected DiarioResponse<T> HttpPutProxy<T>(string url, IDictionary<string, string> data)
        {
            return HttpPut<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithParams(HttpVerbs.Put, url, null, data), data);
        }



        protected DiarioResponse<T> HttpPutProxy<T>(string url, string body)
        {
            return HttpPut<T>(String.Concat(GetApiHost(), url), AuthenticationHeadersWithBody(HttpVerbs.Put, url, null, body), body);
        }



        private DiarioResponse<T> HttpPut<T>(string url, IDictionary<string, string> headers, IDictionary<string, string> data)
        {
            return Http<T>(new Uri(url), HttpVerbs.Put, headers, data);
        }

        private DiarioResponse<T> HttpPut<T>(string url, IDictionary<string, string> headers, string body)
        {
            return Http<T>(new Uri(url), HttpVerbs.Put, headers, body, null, null, null, HttpHeaderContentTypeJson);
        }

        /// <summary>
        /// Calculates the headers to be sent with a request to the API so the server can verify the signature
        /// </summary>
        /// <param name="httpMethod">The HTTP request method.</param>
        /// <param name="querystring">The urlencoded string including the path (from the first forward slash) and the parameters.</param>
        /// <param name="xHeaders">The HTTP request headers specific to the API, excluding X-11Paths-Date. null if not needed.</param>
        /// <param name="params">The HTTP request params. Must be only those to be sent in the body of the request and must be urldecoded. null if not needed.</param>
        /// <returns>A map with the {@value #AuthorizationHeaderName} and {@value #DateHeaderName} headers needed to be sent with a request to the API.</returns>
        private IDictionary<string, string> AuthenticationHeadersWithParams(HttpVerbs httpMethod, string querystring, IDictionary<string, string> xHeaders, IDictionary<string, string> param)
        {
            return AuthenticationHeadersWithParams(httpMethod, querystring, xHeaders, param, GetCurrentUTC());
        }

        private IDictionary<string, string> AuthenticationHeadersWithBody(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, string body)
        {
            byte[] bodyBytes = (body != null) ? Encoding.UTF8.GetBytes(body) : null;
            return AuthenticationHeadersWithBody(httpMethod, queryString, xHeaders, bodyBytes, GetCurrentUTC());
        }

        public IDictionary<string, string> AuthenticationHeadersWithFile(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, byte[] file)
        {
            return AuthenticationHeadersWithFile(httpMethod, queryString, xHeaders, file, GetCurrentUTC());
        }

        /// <summary>
        /// Calculate the authentication headers to be sent with a request to the API
        /// </summary>
        /// <param name="httpMethod">The HTTP Method, currently only GET is supported</param>
        /// <param name="querystring">The urlencoded string including the path (from the first forward slash) and the parameters.</param>
        /// <param name="xHeaders">The HTTP request headers specific to the API, excluding X-11Paths-Date. null if not needed.</param>
        /// <param name="params">The HTTP request params. Must be only those to be sent in the body of the request and must be urldecoded. Null if not needed.</param>
        /// <param name="utc">The Universal Coordinated Time for the X-11Paths-Date HTTP header</param>
        /// <returns>A map with the Authorization and X-11Paths-Date headers needed to sign a Latch API request</returns>
        private IDictionary<string, string> AuthenticationHeadersWithParams(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, IDictionary<string, string> param, string utc)
        {
            if (String.IsNullOrEmpty(queryString) || String.IsNullOrEmpty(utc))
            {
                return null;
            }
            return StringToSign(httpMethod, queryString, xHeaders, utc, param);
        }

        /// <summary>
        /// Calculates the headers to be sent with a request to the API so the server can verify the signature
        /// </summary>
        /// <param name="httpMethod">The HTTP request method.</param>
        /// <param name="querystring">The urlencoded string including the path (from the first forward slash) and the parameters.</param>
        /// <param name="xHeaders">The HTTP request headers specific to the API, excluding X-11Paths-Date. null if not needed.</param>
        /// <param name="body">The HTTP request body. Null if not needed.</param>
        /// <param name="utc">The Universal Coordinated Time for the X-11Paths-Date HTTP header</param>
        /// <returns>A map with the {@value #AuthorizationHeaderName}, the {@value #DateHeaderName} and the {@value #BodyHashHeaderName} headers needed to be sent with a request to the API.</returns>
        private IDictionary<string, string> AuthenticationHeadersWithBody(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, byte[] body, string utc)
        {
            if (String.IsNullOrEmpty(queryString) || String.IsNullOrEmpty(utc))
            {
                return null;
            }
            string bodyHash = null;
            if (body != null)
            {
                bodyHash = Utils.Sha1(body);
                if (xHeaders == null)
                {
                    xHeaders = new Dictionary<string, string>();
                }
                xHeaders.Add(BodyHashHeaderName, bodyHash);
            }

            IDictionary<string, string> headers = StringToSign(httpMethod, queryString, xHeaders, utc, null);
            if (bodyHash != null)
            {
                headers.Add(BodyHashHeaderName, bodyHash);
            }
            return headers;
        }

        private IDictionary<string, string> AuthenticationHeadersWithFile(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, byte[] file, string utc)
        {
            if (String.IsNullOrEmpty(queryString) || String.IsNullOrEmpty(utc))
            {
                return null;
            }

            if (file != null)
            {
                string fileHash = Utils.Sha1(file);
                if (xHeaders == null)
                {
                    xHeaders = new Dictionary<string, string>();
                }

                xHeaders.Add(FileHashHeaderName, fileHash);
            }

            IDictionary<string, string> headers = StringToSign(httpMethod, queryString, xHeaders, utc, null);

            return headers;
        }

        private IDictionary<string, string> StringToSign(HttpVerbs httpMethod, string queryString, IDictionary<string, string> xHeaders, string utc, IDictionary<string, string> param)
        {
            string stringToSign = String.Concat(httpMethod.ToString().ToUpper(), "\n", utc, "\n", GetSerializedHeaders(xHeaders), "\n", queryString.Trim());

            {
                string serializedParams = GetSerializedParams(param);
                if (!String.IsNullOrEmpty(serializedParams))
                {
                    stringToSign = String.Concat(stringToSign, "\n", serializedParams);
                }
            }
            string signedData = String.Empty;
            try
            {
                signedData = SignData(stringToSign.ToString());
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }

            string authorizationHeader = String.Concat(AuthorizationMethod, AuthorizationHeaderFieldSeparator, this.AppId, AuthorizationHeaderFieldSeparator, signedData);

            IDictionary<string, string> headers = new Dictionary<string, string>
            {
                { AuthorizationHeaderName, authorizationHeader },
                { DateHeaderName, utc }
            };
            return headers;
        }

        /// <summary>
        /// Signs the data provided in order to prevent tampering
        /// </summary>
        /// <param name="data">The string to sign</param>
        /// <returns>Base64 encoding of the HMAC-SHA1 hash of the data parameter using <code>secretKey</code> as cipher key.</returns>
        private string SignData(string data)
        {
            if (String.IsNullOrEmpty(data))
            {
                throw new ArgumentException("String to sign can not be null or empty.");
            }
            if (String.IsNullOrEmpty(SecretKey))
            {
                throw new NullReferenceException("String used to sign can not be null or empty.");
            }
            using (HMACSHA1 hmacSha1 = new HMACSHA1(Encoding.ASCII.GetBytes(SecretKey)))
            {
                return Convert.ToBase64String(hmacSha1.ComputeHash(Encoding.ASCII.GetBytes(data)));
            }
        }

        /// <summary>
        /// Performs an HTTP request to an URL using the specified method and data, returning the response as a string
        /// </summary>
        protected virtual DiarioResponse<T> Http<T>(Uri url, HttpVerbs method, IDictionary<string, string> headers, IDictionary<string, string> data)
        {
            string body = GetSerializedParams(data);
            return Http<T>(url, method, headers, body, null, null, null, HttpHeaderContentTypeFormUrlencoded);
        }

        /// <summary>
        /// Performs an HTTP request to an URL using the specified method, headers and data, returning the response as a string
        /// </summary>
        protected virtual DiarioResponse<T> Http<T>(Uri url, HttpVerbs method, IDictionary<string, string> headers, string body, HttpPostedFileBase file, 
            byte[] fileBytes, string filename,  string contentType)
        {

            HttpWebRequest request = BuildHttpUrlConnection(url, headers);

            if (request == null)
            {
                throw new HttpException("Request could not be created correctly");
            }
            request.Method = method.ToString();

            try
            {
                if (method.Equals(HttpVerbs.Post) || method.Equals(HttpVerbs.Put))
                {
                    if (body != null && file == null)
                    {
                        request.ContentType = contentType;
                        request.ContentLength = body.Length;
                        using (StreamWriter streamWriter = new StreamWriter(request.GetRequestStream()))
                        {
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(body);
                            streamWriter.Write(body);
                            streamWriter.Flush();
                            streamWriter.Close();
                        }

                    }
                    else
                    {
                        var client = new HttpClient();
                        if (headers != null)
                        {
                            foreach (KeyValuePair<string, string> pair in headers)
                            {
                                client.DefaultRequestHeaders.Add(pair.Key, pair.Value);
                            }
                        }

                        var message = new HttpRequestMessage()
                        {
                            Method = method == HttpVerbs.Post ? HttpMethod.Post : HttpMethod.Put,
                            RequestUri = url,
                            Content = new MultipartFormDataContent { { new ByteArrayContent(fileBytes), "file", filename } }
                        };

                        var response = client.SendAsync(message).Result;

                        return new DiarioResponse<T>(response.Content.ReadAsStringAsync().Result);

                    }
                }

                using (StreamReader sr = new StreamReader(request.GetResponse().GetResponseStream()))
                {
                    string json = sr.ReadToEnd();
                    return new DiarioResponse<T>(json);
                }
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        private HttpWebRequest BuildHttpUrlConnection(Uri url, IDictionary<string, string> headers)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

            if (Proxy != null)
            {
                request = BuildHttpUrlConnectionProxy(request);
            }

            foreach (string key in headers.Keys)
            {
                if (key.Equals(AuthorizationHeaderName, StringComparison.InvariantCultureIgnoreCase))
                {
                    request.Headers[AuthorizationHeaderName] = headers[key];
                }
                else if (key.Equals(DateName, StringComparison.InvariantCultureIgnoreCase))
                {
                    try
                    {
                        request.Date = DateTime.Parse(headers[key], null, System.Globalization.DateTimeStyles.AssumeUniversal);
                    }
                    catch (Exception e)
                    {
                        Tracer.Instance.TraceAndOutputError(e.ToString());
                        return null;
                    }
                }
                else
                {
                    request.Headers.Add(key, headers[key]);
                }
            }
            return request;
        }

        private HttpWebRequest BuildHttpUrlConnectionProxy(HttpWebRequest request)
        {
            if (!String.IsNullOrEmpty(Proxy.Host))
            {
                request.Proxy = new WebProxy(Proxy.Host, Proxy.Port);
                if (!String.IsNullOrEmpty(Proxy.User) && !String.IsNullOrEmpty(Proxy.Password))
                {
                    if (!String.IsNullOrEmpty(Proxy.Domain))
                    {
                        request.Proxy.Credentials = new NetworkCredential(
                            Proxy.User,
                            Proxy.Password,
                            Proxy.Domain);
                    }
                    else
                    {
                        request.Proxy.Credentials = new NetworkCredential(
                            Proxy.User,
                            Proxy.Password);
                    }
                }
            }
            return request;
        }

        /// <summary>
        /// Returns a string representation of the current time in UTC to be used in a Date HTTP Header
        /// </summary>
        protected virtual string GetCurrentUTC()
        {
            return DateTime.UtcNow.ToString(UtcStringFormat);
        }

        private static long GetMillisecondsFromEpoch(DateTime date)
        {
            return (long)(date.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
        }

        /// <summary>
        /// Encodes a string to be passed as an URL parameter in UTF-8
        /// </summary>
        private static string UrlEncode(string value)
        {
            return Uri.EscapeDataString(value).Replace("%20", "+");
        }

        protected abstract string GetApiHost();

        #region Static Methods

        /// <summary>
        /// The custom header consists of three parts: the method, the application ID and the signature.
        /// This method returns the specified part if it exists.
        /// </summary>
        /// <param name="part">The zero indexed part to be returned</param>
        /// <param name="header">The HTTP header value from which to extract the part</param>
        /// <returns>The specified part from the header or an empty string if not existent</returns>
        private static string GetPartFromHeader(HeaderPart headerPart, string header)
        {
            int part = (int)headerPart;
            if (part < 0)
            {
                return String.Empty;
            }
            if (!String.IsNullOrEmpty(header))
            {
                string[] parts = header.Split(AuthorizationHeaderFieldSeparator);
                if (parts.Length > part)
                {
                    return parts[part];
                }
            }
            return String.Empty;
        }

        /// <summary>
        /// Extracts the authorization method from the authorization header (the first parameter)
        /// </summary>
        /// <param name="authorizationHeader">Authorization HTTP Header</param>
        /// <returns>The Authorization method. Typical values are "Basic", "Digest" or "11PATHS"</returns>
        private static string GetAuthMethodFromHeader(string authorizationHeader)
        {
            return GetPartFromHeader(HeaderPart.Signature, authorizationHeader);
        }

        /// <summary>
        /// Extracts the application ID from the authorization header (the second parameter)
        /// </summary>
        /// <param name="authorizationHeader">Authorization HTTP Header</param>
        /// <returns>The requesting application Id. Identifies the application using the API</returns>
        private static string GetAppIdFromHeader(string authorizationHeader)
        {
            return GetPartFromHeader(HeaderPart.AppId, authorizationHeader);
        }

        /// <summary>
        /// Extracts the signature from the authorization header (the third parameter)
        /// </summary>
        /// <param name="authorizationHeader">Authorization HTTP Header</param>
        /// <returns>The signature of the current request. Verifies the identity of the application using the API</returns>
        private static string GetSignatureFromHeader(string authorizationHeader)
        {
            return GetPartFromHeader(HeaderPart.AuthMethod, authorizationHeader);
        }

        private static string ParseQueryParams(IDictionary<string, string> queryParams)
        {
            if (queryParams == null || queryParams.Count == 0)
            {
                return String.Empty;
            }

            string query = QueryStringDelmiter;
            foreach (string key in queryParams.Keys)
            {
                string value = queryParams[key];
                if (!String.IsNullOrEmpty(value))
                {
                    query += key + ParamValueSeparator + UrlEncode(value) + ParamSeparator;
                }
            }
            return (query.EndsWith(ParamSeparator.ToString())) ? query.Substring(0, query.Length - 1) : query;
        }

        /// <summary>
        /// Prepares and returns a string ready to be signed from the 11-paths specific HTTP headers received
        /// </summary>
        /// <param name="xHeaders">A non necessarily sorted IDictionary of the HTTP headers</param>
        /// <returns>A string with the serialized headers, an empty string if no headers are passed, or a ApplicationException if there's a problem
        ///  such as non specific 11paths headers</returns>
        private static string GetSerializedHeaders(IDictionary<string, string> xHeaders)
        {
            if (xHeaders != null)
            {
                SortedDictionary<string, string> sorted = new SortedDictionary<string, string>();

                foreach (string key in xHeaders.Keys)
                {
                    if (!key.StartsWith(X11PathsHeaderPrefix, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new ApplicationException("Error serializing headers. Only specific " + X11PathsHeaderPrefix + " headers need to be signed");
                    }
                    sorted.Add(key.ToLowerInvariant(), xHeaders[key].Replace('\n', ' '));
                }

                string serializedHeaders = String.Empty;
                foreach (string key in sorted.Keys)
                {
                    serializedHeaders = String.Concat(serializedHeaders, key, X11PathsHeaderSeparator, sorted[key], AuthorizationHeaderFieldSeparator);
                }

                return serializedHeaders.Trim(AuthorizationHeaderFieldSeparator);
            }
            else
            {
                return String.Empty;
            }
        }


        /// <summary>
        /// Prepares and returns a string ready to be signed from the parameters of an HTTP request
        /// </summary>
        /// <param name="parameters">A non necessarily sorted IDictionary of the parameters</param>
        /// <returns>A string with the serialized parameters, an empty string if no headers are passed</returns>
        /// <remarks> The params must be only those included in the body of the HTTP request when its content type
        ///     is application/x-www-urlencoded and must be urldecoded. </remarks>
        private static string GetSerializedParams(IDictionary<string, string> parameters)
        {
            if (parameters != null)
            {
                SortedDictionary<string, string> sorted = new SortedDictionary<string, string>(parameters);

                string serializedParams = String.Empty;
                Regex reg = new Regex(@"%[a-f0-9]{2}");     //Hex words have to be uppercase
                foreach (string key in sorted.Keys)
                {
                    string lowerKey = UrlEncode(sorted[key]);
                    string upperKey = reg.Replace(lowerKey, m => m.Value.ToUpperInvariant());
                    string lowerValue = UrlEncode(key);
                    string upperValue = reg.Replace(lowerValue, m => m.Value.ToUpperInvariant());
                    serializedParams = String.Concat(serializedParams, upperValue, ParamValueSeparator);
                    serializedParams = String.Concat(serializedParams, upperKey, ParamSeparator);
                }

                return serializedParams.Trim(ParamSeparator);
            }
            else
            {
                return String.Empty;
            }
        }

        #endregion Static Methods
    }
}

