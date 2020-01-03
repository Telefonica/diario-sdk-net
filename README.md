### DIARIO .NET SDK ###

DIARIO bridges a natural gap that antiviruses do not usually match. DIARIO is not intended to replace antiviruses, but to cover the gap with fresh samples: DIARIO is especially good detecting them. DIARIO helps detect fresh malware without compromising your privacy or sharing content.



#### Prerequisites ####

* .NET Framework 4.6.1+


* A valid account in DIARIO (https://diario.e-paths.com/index.html) in order to get a **APP_ID** and **SECRET_KEY** keys (Registration is FREE).


#### Installation ####

```
    Download and import DiarioSDKNet.dll to your project or solution.
```


#### Minimal usage ####


* Create a DIARIO object with the "Application ID" and "Secret" previously obtained.
```
   var diario = new Diario(appId, secretKey);
```

'host' and 'port' default parameters are set to diario-elevenlabs.e-paths.com and 443.


* Call to DIARIO Server to do searches, upload and analyze documents, ...
```
	var response_search = diario.Search("e92cf597bdaf49c2e5122ac442514fbe5ab3192a3575958edcdceb3a0dc49de6");
```

* After every API call, get DIARIO response data and errors and handle them.
```
	Console.WriteLine("Response Search: " + response_search)
```

* Others Methods.
```
	 diario.Upload(fullFilePath);
	 
	 diario.Tags(documentHash, tags);

	 diario.GetMacroInfo(documentHash);

	 diario.GetJavaScriptInfo(documentHash)
```

#### REST API specification ####

* Rest API documentation (https://diario.e-paths.com/api-specification.html).
