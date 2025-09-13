dotnet tool install --global dotnet-svcutil
dotnet-svcutil --verbosity Debug --sync --serviceContract ^
	./ehealth-commons/XSD/*.xsd ./ehealth-errors/XSD/*.xsd ./ehealth-etee/XSD/*.xsd ^
	./ehealth-mycarenetcommons/XSD/*.xsd ./ehealth-mycarenet-memberdata/XSD/*.xsd ^
	./external/XSD/*.xsd ./SAML/XSD/*.xsd ^
	./ehealth-mycarenet-memberdata/WSDL/mycarenet-memberdata-proxy-v1.wsdl ^
	./ehealth-etee/WSDL/etkdepot-proxy-v1.wsdl
