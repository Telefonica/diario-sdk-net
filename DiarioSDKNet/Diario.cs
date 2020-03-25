using BaseSDK;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web.Script.Serialization;

namespace DiarioSDKNet
{
    public class Diario : ApiAuth
    {
        public const string ApiVersion = "0.1";
        public const string ApiHost = "https://diario.elevenpaths.com";
        public const string DefaultUrl = "/api/" + ApiVersion + "/";

        public const string PathSearch = DefaultUrl + "search";
        public const string PathUpload = DefaultUrl + "upload";
        public const string PathTags = DefaultUrl + "tags";
        public const string AnonymousUpload = "/anonymous-upload";
        public const string PathValidate = "/validate";

        public const string PathMacro = "/macro";
        public const string PathJavascript = "/javascript";
        public const string PathModel = "/model";
        public const string PathModelLastVersion = PathModel + "/last-versions";
        public const string PathModelDeployed = PathModel + "/deployed";
        public const string PathModelStatistics = PathModel + "/statistics";
        public const string PathModelTrain = PathModel + "/train";
        public const string PathModelDeploy = PathModel + "/deploy";

        public const string Pdf = "pdf";
        public const string Office = "office";

        public enum Prediction { Goodware = 0, Malware = 1, NoMacros = 2, Unknown = 3 };

        public enum Model { NEURAL_NETWORK = 0, RANDOM_FOREST = 1, DECISION_TREE = 2, SVM = 3 };

        public Diario(string appId, string secretKey)
            : base(ApiHost, appId, secretKey)
        {
        }

        public Diario(string apiBaseUrl, string appId, string secretKey)
            : base(apiBaseUrl, appId, secretKey)
        {
        }

        public Diario(string appId, string secretKey, WebProxy proxy)
            : base(ApiHost, appId, secretKey, proxy)
        {
        }

        /// <summary>
        ///  Gets string of prediction base on Enum
        /// </summary>
        /// <param name="prediction"></param>
        /// <returns>Return char G (Goodware) or M (Malware)</returns>
        private static string GetStringPredictonFromPrediction(Prediction prediction)
        {
            try
            {
                switch (prediction)
                {
                    case Prediction.Goodware:
                        return "G";

                    case Prediction.Malware:
                        return "M";

                    default:
                        return null;
                }
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        public static Prediction GetPredictonFromString(string prediction)
        {
            switch (prediction)
            {
                case "G":
                    return Prediction.Goodware;
                case "M":
                    return Prediction.Malware;
                case "NM":
                    return Prediction.NoMacros;
                case "U":
                    return Prediction.Unknown;
                default:
                    throw new ArgumentException("Invalid value", nameof(prediction));
            }
        }

        /// <summary>
        ///  Gets string of Model base on Enum
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Return char G (Goodware) or M (Malware)</returns>
        private static string GetStringModelFromModel(Model model)
        {
            try
            {
                switch (model)
                {
                    case Model.NEURAL_NETWORK:
                        return "nn";

                    case Model.SVM:
                        return "svm";

                    case Model.RANDOM_FOREST:
                        return "rf";

                    case Model.DECISION_TREE:
                        return "dt";

                    default:
                        return null;
                }
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        ///  Gets DIARIO prediction and information for a specific document. The prediction could be M (Malware), G(Goodware) and NM (No Macros presence). 
        ///  The prediction NM is only for office documents. The posible stages are A (Analyzed), P (Processing) and F (Failed). 
        ///  The office documents also shall contain the field "type" in the response that could be word or excel. 
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <returns>Return json data frame based on the type of PDF or OFFICE document with the data associated with its previous analysis</returns>
        public ApiResponse<dynamic> Search(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return GetHttpRequest<dynamic>(PathSearch, data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Upload an Office or PDF document for predicting
        /// </summary>
        /// <param name="fullFilePath">Local file path to upload to API REST</param>
        /// <returns>SHA2-256 hash returned by API REST after successful file upload</returns>
        public ApiResponse<dynamic> Upload(string fullFilePath)
        {
            byte[] fileBytes = File.ReadAllBytes(fullFilePath);
            string fileName = Path.GetFileName(fullFilePath);

            return Upload(fileBytes, fileName);
        }

        public ApiResponse<dynamic> Upload(byte[] filecontent, string filename)
        {
            if (filecontent == null)
                throw new ArgumentNullException(nameof(filecontent));
            if (String.IsNullOrWhiteSpace(filename))
                throw new ArgumentNullException(nameof(filename));

            try
            {
                return PostHttpRequest<dynamic>(PathUpload, filecontent, filename);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Tag an Office or PDF document
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <param name="tags">A list of tags. The maximum number of tags per document and user is 5.</param>
        /// <returns>receive json data frame based on sent tags</returns>
        public ApiResponse<dynamic> Tags(string documentHash, List<string> tags)
        {
            try
            {
                var jsonSerialiser = new JavaScriptSerializer();
                var jsonTags = jsonSerialiser.Serialize(tags); ;

                string postData = "{ \"tags\":" + jsonTags + ", \"hash\":\"" + documentHash + "\" }";

                return PostHttpRequest<dynamic>(PathTags, postData);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Get the information of a certain macro. 
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <returns>Return json data frame based of OFFICE. If it is cataloged as malware, it returns macro source code.</returns>
        public ApiResponse<dynamic> GetMacroInfo(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return GetHttpRequest<dynamic>(DefaultUrl + Office + PathMacro, data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Get the information of a certain javascript.. 
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <returns>Return json data frame based of PDF. If it is cataloged as malware, it returns js source code.</returns>
        public ApiResponse<dynamic> GetJavaScriptInfo(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return GetHttpRequest<dynamic>(DefaultUrl + Pdf + PathJavascript, data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the latest version of each machine learning model base on PDF
        /// </summary>
        /// <returns>Return json data frame of each machine learning model.</returns>
        public ApiResponse<dynamic> GetOfficeModelsLastVersions()
        {
            try
            {
                return GetHttpRequest<dynamic>(DefaultUrl + Office + PathModelLastVersion, null);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the latest version of each machine learning mode base on Office Document
        /// </summary>
        /// <returns>Return json data frame of each machine learning model.</returns>
        public ApiResponse<dynamic> GetPdfModelsLastVersions()
        {
            try
            {
                return GetHttpRequest<dynamic>(DefaultUrl + Pdf + PathModelLastVersion, null);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Manually validate (or correct) the system prediction for a specified document. 
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <param name="prediction">string G o M (Goodware or Malware)</param>
        /// <returns>Return the json data frame with the hash matching the PDF Doc</returns>
        public ApiResponse<dynamic> ValidatePdfDocument(string documentHash, Prediction prediction)
        {
            try
            {
                var postData = "{ \"hash\":" + documentHash + ", \"prediction\":\"" + GetStringPredictonFromPrediction(prediction) + "\" }";
                return PostHttpRequest<dynamic>(DefaultUrl + Pdf + PathValidate, postData);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Manually validate (or correct) the system prediction for a specified document. 
        /// </summary>
        /// <param name="documentHash">SHA2-256 hash</param>
        /// <param name="prediction">string G o M (Goodware or Malware)</param>
        /// <returns>Return the json data frame with the hash matching the Office Doc</returns>
        public ApiResponse<dynamic> ValidateOfficeDocument(string documentHash, Prediction prediction)
        {
            try
            {
                var postData = "{ \"hash\":" + documentHash + ", \"prediction\":\"" + GetStringPredictonFromPrediction(prediction) + "\" }";
                return PostHttpRequest<dynamic>(DefaultUrl + Office + PathValidate, postData);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the algorithm and its version used to predict PDF document. 
        /// </summary>
        /// <returns>Return the json data frame with model name and version</returns>
        public ApiResponse<dynamic> GetPdfModelDeployed()
        {
            try
            {
                return GetHttpRequest<dynamic>(DefaultUrl + Pdf + PathModelDeployed, null);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the algorithm and its version used to predict Office document. 
        /// </summary>
        /// <returns>Return the json data frame with model name and version</returns>
        public ApiResponse<dynamic> GetOfficeModelDeployed()
        {
            try
            {
                return GetHttpRequest<dynamic>(DefaultUrl + Office + PathModelDeployed, null);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the information related to the statistics of a certain model for PDF
        /// <param name="model"></param>
        /// <param name="version"></param>
        /// </summary>
        /// <returns>Return the json data of model</returns>
        public ApiResponse<dynamic> GetPdfModelStatistics(Model model, int version)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("model", GetStringModelFromModel(model));
                data.Add("version", version.ToString());

                return GetHttpRequest<dynamic>(DefaultUrl + Pdf + PathModelStatistics, data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Get the information related to the statistics of a certain model for Office
        /// <param name="model"></param>
        /// <param name="version"></param>
        /// </summary>
        /// <returns>Return the json data of model</returns>
        public ApiResponse<dynamic> GetOfficeModelStatistics(Model model, int version)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("model", GetStringModelFromModel(model));
                data.Add("version", version.ToString());

                return GetHttpRequest<dynamic>(DefaultUrl + Office + PathModelStatistics, data);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Update a certain model from its ID (model) for PDF documents.
        /// <param name="model">model nam</param>
        /// </summary>
        /// <returns>Return json message: Done or Error</returns>
        public ApiResponse<dynamic> TrainPdfModel(Model model)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\" } ";
                return PostHttpRequest<dynamic>(DefaultUrl + Pdf + PathModelTrain, postData);

            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Update a certain model from its ID (model) for Office documents.
        /// <param name="model">model nam</param>
        /// </summary>
        /// <returns>Return json message: Done or Error</returns>
        public ApiResponse<dynamic> TrainOfficeModel(Model model)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\" } ";
                return PostHttpRequest<dynamic>(DefaultUrl + Office + PathModelTrain, postData);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Deploy the selected machine learning model and version for PDF documents.
        /// <param name="model">model nam</param>
        /// <param name="version">version model</param>
        /// </summary>
        /// <returns>Return json message: Done or Error</returns>
        public ApiResponse<dynamic> DeployPdfModel(Model model, int version)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\",  \"version\" : \"" + version + "\"} ";
                return PostHttpRequest<dynamic>(DefaultUrl + Pdf + PathModelDeploy, postData);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// [ADMIN] Deploy the selected machine learning model and version for Office documents.
        /// <param name="model">model nam</param>
        /// <param name="version">version model</param>
        /// </summary>
        /// <returns>Return json message: Done or Error</returns>
        public ApiResponse<dynamic> DeployOfficeModel(Model model, int version)
        {
            try
            {
                var postdata = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\",  \"version\" : \"" + version + "\"} ";
                return PostHttpRequest<dynamic>(DefaultUrl + Office + PathModelDeploy, postdata);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }
    }
}
