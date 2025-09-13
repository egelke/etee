dotnet tool install --global dotnet-svcutil
dotnet-svcutil --sync --internal --serviceContract  ./ehealth-iam/WSDL/ehealth-iam-sts-ws-trust-1.3-proxy-v1.wsdl ./external/XSD/*.xsd
REM svcutil.exe /serviceContract /internal /out:Reference.cs  ./ehealth-iam/WSDL/ehealth-iam-sts-ws-trust-1.3-proxy-v1.wsdl ./external/XSD/*.xsd