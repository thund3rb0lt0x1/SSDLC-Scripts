"""
Custom SSL/TLS Weak Cipher Detection Scan Rule for ZAP (Jython Active Rule)
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata
from java.net import InetSocketAddress
from javax.net.ssl import SSLContext, SSLSocketFactory
from javax.net.ssl import TrustManager, X509TrustManager

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 4000401
name: SSL/TLS Weak Cipher Detection (Custom Jython Active Rule)
description: Detects if the server supports weak or insecure SSL/TLS cipher suites by enumerating available cipher suites across multiple TLS versions.
solution: Disable weak cipher suites and use strong encryption with forward secrecy in server configuration.
references:
  - https://owasp.org/www-project-top-ten/
  - https://www.ssllabs.com/
category: MISC
risk: MEDIUM
confidence: HIGH
cweId: 310
wascId: 13
alertTags:
  OWASP_2021_A05: Security Misconfiguration
  OWASP_2017_A06: Security Misconfiguration
otherInfo: Custom script-based detection of weak SSL/TLS cipher suites using Java SSL APIs.
status: alpha
""")

def scanNode(helper, msg):
    # Node scan not needed for this rule
    pass

def scan(helper, msg, param, value):
    try:
        host = msg.getRequestHeader().getHostName()
        port = msg.getRequestHeader().getHostPort()
        if port == -1:
            port = 443

        weak_ciphers = ["NULL", "EXPORT", "LOW", "RC4", "DES", "MD5", "PSK", "aNULL", "eNULL"]
        tls_versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        insecure_found = []

        class DummyTrustManager(X509TrustManager):
            def checkClientTrusted(self, chain, authType): pass
            def checkServerTrusted(self, chain, authType): pass
            def getAcceptedIssuers(self): return None

        for tls_version in tls_versions:
            try:
                context = SSLContext.getInstance(tls_version)
                context.init(None, [DummyTrustManager()], None)
                factory = context.getSocketFactory()
                
                ssl_socket = factory.createSocket()
                ssl_socket.connect(InetSocketAddress(host, port), 5000)
                ssl_socket.setSoTimeout(5000)
                
                enabled_ciphers = ssl_socket.getSupportedCipherSuites()
                accepted_ciphers = []
                
                for cipher in enabled_ciphers:
                    try:
                        ssl_socket.setEnabledCipherSuites([cipher])
                        ssl_socket.startHandshake()
                        accepted_ciphers.append(cipher)
                    except:
                        pass
                
                for cipher in accepted_ciphers:
                    for weak in weak_ciphers:
                        if weak in cipher:
                            insecure_found.append((tls_version, cipher))
                            break
                
                ssl_socket.close()
                
            except Exception as e:
                pass  # TLS version not supported or handshake failed

        print("Scanned this host: {}:{}".format(host, port))

        if insecure_found:
            alert = helper.newAlert()
            alert.setRisk(2)  # Medium
            alert.setConfidence(3)  # High
            alert.setName("SSL/TLS Weak Cipher Suites Detected")
            alert.setDescription("The server supports weak cipher suites or insecure TLS versions that may compromise communication security.")
            alert.setSolution("Disable weak cipher suites and use strong encryption algorithms with forward secrecy.")
            alert.setReference("https://owasp.org/www-project-top-ten/")
            evidence_list = []
            for version, cipher in insecure_found:
                evidence_list.append(version + " : " + cipher)
            alert.setEvidence(", ".join(evidence_list))
            alert.setMessage(msg)
            alert.raise()

    except Exception as e:
        print("Error scanning host {}:{} -> {}".format(host, port, e))
