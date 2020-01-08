using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

namespace DiarioSDKNet
{
    public class Diario : BaseSdk
    {

        public const string ApiVersion = "0.1";
        public const string ApiHost = "https://diario-elevenlabs.e-paths.com";
        public const string DefaultUrl = "/api/" + ApiVersion + "/";

        public const string PathSearch = DefaultUrl + "search";
        public const string PathUpload = DefaultUrl + "upload";
        public const string PathTags = DefaultUrl + "tags";
        public const string AnonymousUpload = "/anonymous-upload";
        public const string PathValidate = "/validate";

        public const string GetInfo = DefaultUrl + "";

        public const string PathMacro = "/macro";
        public const string PathJavascript = "/javascript";
        public const string PathModel = "/model";
        public const string PathModelLastVersion = PathModel + "/last-versions";
        public const string PathModelDeployed = PathModel + "/deployed";
        public const string PathModelStatistics = PathModel + "/statistics";
        public const string PathModelTrain = PathModel + "/train";
        public const string PathModelDeploy = PathModel + "/deploy";

        public const string BaseURLOpen = "/open/api";
        public const string CHANGE = BaseURLOpen + "/change";

        public const string ParamHash = "hash";
        public const string ParamFile = "file";
        public const string ParamPrediction = "prediction";
        public const string ParamModel = "model";
        public const string ParamVersion = "version";
        public const string ParamDocumentType = "documentType";
        public const string ParamEmail = "email";
        public const string ParamDescription = "description";
        public const string ParamTags = "tags";

        public const string Pdf = "pdf";
        public const string Office = "office";

        public enum Prediction { Goodware = 0, Malware = 1 };

        public enum Model { NEURAL_NETWORK = 0, RANDOM_FOREST = 1, DECISION_TREE = 2, SVM = 3 };

        public Diario(string appId, string secretKey)
            : base(appId, secretKey)
        {
        }

        protected override string GetApiHost()
        {
            return ApiHost;
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
        public DiarioResponse<dynamic> Search(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return HttpGetProxy<dynamic>(PathSearch, data);
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
        public DiarioResponse<dynamic> Upload(string fullFilePath)
        {
            try
            {
                byte[] fileBytes = File.ReadAllBytes(fullFilePath);
                string fileName = Path.GetFileName(fullFilePath);

                var headers = new Dictionary<string, string>();

                return HttpPostFileProxy<dynamic>(PathUpload, null, fileBytes, fileName, headers);

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
        public DiarioResponse<dynamic> Tags(string documentHash, List<string> tags)
        {
            try
            {
                var jsonSerialiser = new JavaScriptSerializer();
                var jsonTags = jsonSerialiser.Serialize(tags); ;

                string postData = "{ \"tags\":" + jsonTags + ", \"hash\":\"" + documentHash + "\" }";

                return HttpPostProxy<dynamic>(PathTags, postData);
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
        public DiarioResponse<dynamic> GetMacroInfo(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return HttpGetProxy<dynamic>(DefaultUrl + Office + PathMacro, data);
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
        public DiarioResponse<dynamic> GetJavaScriptInfo(string documentHash)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("hash", documentHash);

                return HttpGetProxy<dynamic>(DefaultUrl + Pdf + PathJavascript, data);
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
        public DiarioResponse<dynamic> GetOfficeModelsLastVersions()
        {
            try
            {
                return HttpGetProxy<dynamic>(DefaultUrl + Office + PathModelLastVersion, null);
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
        public DiarioResponse<dynamic> GetPdfModelsLastVersions()
        {
            try
            {
                return HttpGetProxy<dynamic>(DefaultUrl + Pdf + PathModelLastVersion, null);
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
        public DiarioResponse<dynamic> ValidatePdfDocument(string documentHash, Prediction prediction)
        {
            try
            {
                var postData = "{ \"hash\":" + documentHash + ", \"prediction\":\"" + GetStringPredictonFromPrediction(prediction) + "\" }";
                return HttpPostProxy<dynamic>(DefaultUrl + Pdf + PathValidate, postData);
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
        public DiarioResponse<dynamic> ValidateOfficeDocument(string documentHash, Prediction prediction)
        {
            try
            {
                var postData = "{ \"hash\":" + documentHash + ", \"prediction\":\"" + GetStringPredictonFromPrediction(prediction) + "\" }";
                return HttpPostProxy<dynamic>(DefaultUrl + Office + PathValidate, postData);
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
        public DiarioResponse<dynamic> GetPdfModelDeployed()
        {
            try
            {
                return HttpGetProxy<dynamic>(DefaultUrl + Pdf + PathModelDeployed, null);
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
        public DiarioResponse<dynamic> GetOfficeModelDeployed()
        {
            try
            {
                return HttpGetProxy<dynamic>(DefaultUrl + Office + PathModelDeployed, null);
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
        public DiarioResponse<dynamic> GetPdfModelStatistics(Model model, int version)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("model", GetStringModelFromModel(model));
                data.Add("version", version.ToString());

                return HttpGetProxy<dynamic>(DefaultUrl + Pdf + PathModelStatistics, data);
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
        public DiarioResponse<dynamic> GetOfficeModelStatistics(Model model, int version)
        {
            try
            {
                IDictionary<string, string> data = new Dictionary<string, string>();
                data.Add("model", GetStringModelFromModel(model));
                data.Add("version", version.ToString());

                return HttpGetProxy<dynamic>(DefaultUrl + Office + PathModelStatistics, data);
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
        public DiarioResponse<dynamic> TrainPdfModel(Model model)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\" } ";
                return HttpPostProxy<dynamic>(DefaultUrl + Pdf + PathModelTrain, postData);

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
        public DiarioResponse<dynamic> TrainOfficeModel(Model model)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\" } ";
                return HttpPostProxy<dynamic>(DefaultUrl + Office + PathModelTrain, postData);
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
        public DiarioResponse<dynamic> DeployPdfModel(Model model, int version)
        {
            try
            {
                var postData = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\",  \"version\" : \"" + version + "\"} ";
                return HttpPostProxy<dynamic>(DefaultUrl + Pdf + PathModelDeploy, postData);
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
        public DiarioResponse<dynamic> DeployOfficeModel(Model model, int version)
        {
            try
            {
                var postdata = "{ \"model\" : \"" + GetStringModelFromModel(model) + "\",  \"version\" : \"" + version + "\"} ";
                return HttpPostProxy<dynamic>(DefaultUrl + Office + PathModelDeploy, postdata);
            }
            catch (Exception e)
            {
                Tracer.Instance.TraceAndOutputError(e.ToString());
                return null;
            }
        }
    }
}
