#/* SINGLE/MULTI/WIN32 device version */
option(FEATPROD_MULTI_DEVICE "Enables IP MULTI DEVICE product version" ON)
option(FEATPROD_APPLICATION		  "Build the STX example applications" ON)
option(FEATPROD_BSDSOCK_SUPPORTED "Enables Win32-Socket usage - controlled via 'VsStudio'" OFF)

#/* IPV4 BASIC protocols */
option(FEATPROD_IPV4_SUPPORTED "Enables IPV4" OFF)
option(FEATPROD_IP_FRAG_SUPPORTED "Enables IPv4-Reassm./Fragm. module" OFF)
option(FEATPROD_ICMP_SUPPORTED "Enables ICMP-Ping responses" OFF)
option(FEATPROD_IGMP_SUPPORTED "Enables IGMP (please consider to set IGMP_VERSION3_SUPPORTED additionally)" OFF)

#/* IPV6 BASIC protocols */
option(FEATPROD_IPV6_SUPPORTED "Enables IPV6" ON)
option(FEATPROD_IPV6_FRAG_SUPPORTED "Enables IPv6-Reassm./Fragm. module" ON)

#/* UDP based protocols */
option(FEATPROD_UDP_SUPPORTED "Enables UDP" ON)
option(FEATPROD_NTP_SUPPORTED "Enables NTP (Network Time Protocol)" OFF)
option(FEATPROD_TFTP_SUPPORTED "Enables TFTP" OFF)
option(FEATPROD_SYSLOG_SUPPORTED "Enables SYSLOG module" OFF)
option(FEATPROD_SNMP_SUPPORTED "Enables SNMP & MIB module" OFF)
option(FEATPROD_PTP_SUPPORTED "Enables PTP" OFF)

#/* TCP based protocols */
option(FEATPROD_TCP_SUPPORTED "Enables TCP" ON)
option(FEATPROD_TCP_SOCKET_SUPPORTED "Enables TCP Service module." OFF)
option(FEATPROD_TELNET_SUPPORTED "Enables TELNET" OFF)
option(FEATPROD_NVT_SUPPORTED "Enables NVT" OFF)
option(FEATPROD_XMPP_SUPPORTED "Enables XMPP" OFF)
option(FEATPROD_OSCAR_SUPPORTED "Enables OSCAR" OFF)
option(FEATPROD_FTPC_SUPPORTED "Enables FTP Client" OFF)
option(FEATPROD_FTPS_SUPPORTED "Enables FTP Server" OFF)
option(FEATPROD_MQTTC_SUPPORTED "Enables MQTT Client" OFF)
option(FEATPROD_MODBUSTCP_SUPPORTED "Enables ModbusTCP client" OFF)

#/* HTTP based protocols */
option(FEATPROD_HTTP_SUPPORTED "Enables HTTP generator & parser" ON)
option(FEATPROD_HTTPCLNT_SUPPORTED "Enables HTTP client" ON)
option(FEATPROD_HTTPSERV_SUPPORTED "Enables HTTP server" OFF)
option(FEATPROD_HTTPSERVICE_SUPPORTED "Enables HTTP service" OFF)

option(FEATPROD_REST_SUPPORTED "Enables REST HTTP server/client extension" OFF)
option(FEATPROD_XMLGEN_SUPPORTED "Enables XML generator" OFF)
option(FEATPROD_XMLPRS_SUPPORTED "Enables XML parser" OFF)
option(FEATPROD_SOAP_SUPPORTED "Enables SOAP service" OFF)
option(FEATPROD_SOAP_SERVER_SUPPORTED "Enables SOAP server" OFF)
option(FEATPROD_AJAX_SUPPORTED "Enables AJAX HTTP server/client extension" OFF)
option(FEATPROD_JSONGEN_SUPPORTED "Enables JSON Generator module" ON)
option(FEATPROD_JSONPRS_SUPPORTED "Enables JSON Parser module" ON)
option(FEATPROD_WEBDAV_SUPPORTED "Enables WebDAV module" OFF)
option(FEATPROD_WEBSOCKETCLNT_SUPPORTED "Enables WebSocket client" OFF)
option(FEATPROD_WEBSOCKETSERV_SUPPORTED "Enables WebSocket server" OFF)
option(FEATPROD_WEBSOCKET_VFS_SERVER_SUPPORTED "Enables VFS Websocket Server (Application?)" OFF)

#/* Peer-to-peer services/protocols */
option(FEATPROD_P2P_SUPPORTED "Enables P2P (Peer-to-peer service)" OFF)
option(FEATPROD_SIP_SUPPORTED "Enables SIP module" OFF)
option(FEATPROD_SDP_SUPPORTED "Enables SDP module" OFF)
option(FEATPROD_STUN_SUPPORTED "Enables STUN" OFF)
option(FEATPROD_RTP_SUPPORTED "Enables RTP" OFF)

#/* MAIL protocols */
option(FEATPROD_SMTP_SUPPORTED "Enables SMTP" OFF)
option(FEATPROD_IMFGEN_SUPPORTED "Enables IMF (Internet Message Format) generator" OFF)
option(FEATPROD_POP3_SUPPORTED "Enables POP3" OFF)
option(FEATPROD_IMFPRS_SUPPORTED "Enables IMF (Internet Message Format) parser" OFF)
option(FEATPROD_MAIL_SRV_SUPPORTED "Enables Mail Service module" OFF)

#/* NAME SERVICES (UDP-based) */
option(FEATPROD_DNS_SUPPORTED "Enables simple DNS client" OFF)
option(FEATPROD_DNS_SRV_SUPPORTED "Enables enhanced DNS Client-Server" OFF)
option(FEATPROD_MDNS_SUPPORTED "Enables Multicast-DNS & DNS-SD (part of ZeroConf)" OFF)
option(FEATPROD_NBNS_SUPPORTED "Enables NBNS (NetBIOS Name Service, (part of ZeroConf) )" OFF)
option(FEATPROD_NAMESERV_SUPPORTED "Enables name service wrapper module" ON)
option(FEATPROD_MDNS_SRV_SUPPORTED "Enables local MDNS-ResponderService" OFF)
option(FEATPROD_LLMNR_SUPPORTED "Enables local LLMNR name service" OFF)

#/* SERIAL based protocols */
option(FEATPROD_PPP_SUPPORTED "Enables PPP" OFF)
option(FEATPROD_MODEM_SUPPORTED "Enables Modem driver" OFF)
option(FEATPROD_NULLMODEM_SUPPORTED "Enables Nullmodem driver" OFF)
option(FEATPROD_UART_SUPPORTED "Enables sevenstax UART driver" OFF)
option(FEATPROD_LINKSERV_SUPPORTED "Enables modem link service module" OFF)
option(FEATPROD_CMDUART_SUPPORTED "Enables NVT via Uart" OFF)
option(FEATPROD_BINUART_SUPPORTED "Enables Shared BIN Uart Service module" OFF)

#/* ETHERNET based protocols */
option(FEATPROD_ETHERNET_SUPPORTED "Enables Ethernet" ON)
option(FEATPROD_RNDIS_SUPPORTED "Enables RNDIS-MAC Driver (USB)" OFF)
option(FEATPROD_EMAC_SUPPORTED "Enables Ethernet MAC driver (NIC)" ON)
option(FEATPROD_BOOTP_SUPPORTED "Enables BOOTP" OFF)

option(FEATPROD_DHCP_SUPPORTED "Enables DHCP client" OFF)
option(FEATPROD_DHCP_SRV_SUPPORTED "Enables Mini DHCP server" OFF)
option(FEATPROD_DHCPV6_SUPPORTED "Enables DHCPv6 client" OFF)

option(FEATPROD_AUTOIP_SUPPORTED "Enables Auto-IP (part of ZeroConf)" OFF)
option(FEATPROD_ACD_SUPPORTED "Enables ACD" OFF)
option(FEATPROD_SOFTSWITCH_SUPPORTED "Enables Softswitch between EMAC/RNDIS" OFF)
option(FEATPROD_WLAN_SUPPORTED "Enables WLAN NIC Driver etxension and Service" OFF)
option(FEATPROD_VLAN_SUPPORTED "Enables VLAN support in Ethernet module" OFF)
option(FEATPROD_ETHRAW_SUPPORTED "Enables ETH-RAW module." OFF)
option(FEATPROD_BSDSOCKETRAW_SUPPORTED "Enables BSDSOCKET-RAW module." ON)

#/* ROUTING / NAT */
option(FEATPROD_NATPF_SUPPORTED "Enables routing with NAT" OFF)
option(FEATPROD_FORWARD_SUPPORTED "Enables routing with pure forwarding" OFF)

#/* HELPER modules */
option(FEATPROD_RBUFF_SUPPORTED "Enables sevenstax ring buffer helper module" OFF)
option(FEATPROD_RIGHTS_SUPPORTED "Enables user rights management" OFF)
option(FEATPROD_DATETIME_SUPPORTED "Enables date & time module" ON)
option(FEATPROD_STATVAR_SUPPORTED "Enables static variables module" OFF)
option(FEATPROD_RTC_SUPPORTED "Enables (generic) rtc module" ON)
option(FEATPROD_QUEUE_SUPPORTED "Enables standard queue object" OFF)
option(FEATPROD_SYSLOAD_SUPPORTED "Enables logging of system performance" OFF)
option(FEATPROD_SYSTEMLOG_SUPPORTED "Controls sevenstax System Log: 0=off, 1=SYSLOG, 2=?" OFF)
option(FEATPROD_XBAR_SUPPORTED "Enables universal configuration module 'Crossbar'" OFF)
option(FEATPROD_NVT_XBARLINK_SUPPORTED "Enables XBAR Connection to NVT." OFF)
option(FEATPROD_SETUP_SUPPORTED "Enable Setup Module" OFF)
option(FEATPROD_FIFO_SUPPORTED "Enables sevenstax fifo module" OFF)
option(FEATPROD_SESSION_SUPPORTED "Enables session module" ON)
option(FEATPROD_JWT_SUPPORTED "Enables JWT module" OFF)

option(FEATPROD_PARSESTR_SUPPORTED "parse string module support" ON)
option(FEATPROD_PRINTSTR_SUPPORTED "print string module support" OFF)
option(FEATPROD_DATACONVERTER_SUPPORTED "dataconverter support" OFF)

option(FEATPROD_FRAMING_SUPPORTED "Enables FRAMING Service module " OFF)
option(FEATPROD_MTP_FRAMING_SUPPORTED     "Framing over Ethernet " OFF)

option(FEATPROD_BASE64_SUPPORTED "Base 64" ON)
option(FEATPROD_BER_SUPPORTED "Basic encoding rules" ON)

#/* FILE Handling */
option(FEATPROD_VFS_SUPPORTED "Enables Vitual Filesystem" ON)
option(FEATPROD_UNIXFS_SUPPORTED "Enables Unix Filesystem" ON)
option(FEATPROD_ROMFILES_SUPPORTED "Enables VFS ROM-Files Interface (RessourceGen)" OFF)
option(FEATPROD_FAT_SUPPORTED "Enables VFS FAT-Filesystem" OFF)
option(FEATPROD_FILE_LOOKUP_SUPPORTED "Enables VFS LookupTable Interface (Dir2Flash)" OFF)
option(FEATPROD_STXFS_SUPPORTED "Enables VFS STX-Filesystem Interface (Dir2Flash)" OFF)
option(FEATPROD_SERIAL_FLASH_SUPPORTED "Enables SerialFlash-Interface" OFF)
option(FEATPROD_MCI_SUPPORTED "Enables MMC/SD-Card-Interface" OFF)
option(FEATPROD_USERFILES_SUPPORTED "Enables Userfile module." ON)
option(FEATPROD_USER_STORAGE_SUPPORTED "Enables VFS User storage support" OFF)
option(FEATPROD_REMOTE_FS_SUPPORTED "Enables VFS remote file system support" OFF)
option(FEATPROD_SECURE_FLASH_SUPPORTED "Enables Serial FLASH Encryption support" OFF)

#/* ENCRYPT - Math */
option(FEATPROD_BIGMATH_SUPPORTED "Enables BigMath support" ON)
option(FEATPROD_ECMATH_SUPPORTED "Enables ECMath support" ON)
option(FEATPROD_XCRYPT_SUPPORTED "XCrypt support in the refapp" OFF)

#/* ENCRYPT - HMAC */
option(FEATPROD_HMAC_SUPPORTED "Enables HMAC support" ON)
option(FEATPROD_HKDF_SUPPORTED "Enables HMAC HKDF support" ON)

# ENCRYPT - Random Number Generation
option(FEATPROD_ENTROPY_SUPPORTED "Enables entropy pool" ON)
option(FEATPROD_HMAC_DRBG_SUPPORTED "Enables HMAC DRBG support" ON)

#/* ENCRYPT - TLS and X509 */
option(FEATPROD_TLSSERV_SUPPORTED "Enables TLS server." ON)
option(FEATPROD_TLSCLNT_SUPPORTED "Enables TLS client." OFF)
option(FEATPROD_TLS13_SERV_SUPPORTED "Enables TLS server." OFF)
option(FEATPROD_TLS13_CLNT_SUPPORTED "Enables TLS client." OFF)
option(FEATPROD_X509PARSER_SUPPORTED "Enables X509 (X.509 Certificates)" ON)
option(FEATPROD_X509REQUEST_SUPPORTED "Enables Certificate Renewal Helper." ON)
option(FEATPROD_X509MNGR_SUPPORTED "Enables Certificate Manager module." ON)
option(FEATPROD_OCSP_SUPPORTED "Enables OCSP." ON)

#/* ENCRYPT - Hash functions. */
option(FEATPROD_SHA256_SUPPORTED "Enables SHA256 and SHA224 (Secure Hash Algorithm - 256 and 224 Bit)" ON)
option(FEATPROD_SHA512_SUPPORTED "Enables SHA512 and SHA384 (Secure Hash Algorithm - 512 and 384 Bit)" ON)
option(FEATPROD_SHA3_SUPPORTED "Enables SHA3 (Secure Hash Algorithm 3)" ON)
option(FEATPROD_XTEA_SUPPORTED "Enables XTEA (Extended tiny encryption algorithm) module" OFF)
option(FEATPROD_AES_128_SUPPORTED "Enables AES with 128 bit key length" ON)
option(FEATPROD_AES_192_SUPPORTED "Enables AES with 192 bit key length" ON)
option(FEATPROD_AES_256_SUPPORTED "Enables AES with 256 bit key length" ON)

#/* ENCRYPT - AES Block cipher modes. */
option(FEATPROD_AES_SUPPORTED "Enables AES module" ON)
option(FEATPROD_CRYPTCFB_SUPPORTED "Enables CFB (Cipher feed back) module" OFF)
option(FEATPROD_CRYPTCBC_SUPPORTED "Enables CFB (Cipher block chaining) module" ON)
option(FEATPROD_XTS_AES_SUPPORTED "Enables XTS mode for AES" OFF)

#/* ENCRYPT - Stream ciphers */
option(FEATPROD_CHACHA20_SUPPORTED "Enables ChaCha20 stream cipher module." OFF)

#/* ENCRYPT - Stream cipher modes */
option(FEATPROD_POLY1305_SUPPORTED "Enables Poly1305 AEAD mode." OFF)

#/* ENCRYPT - Asymmetric cryptography. */
option(FEATPROD_RSA_SUPPORTED "Enables RSA (public key cryptography) module" ON)
option(FEATPROD_DH_SUPPORTED "Enables DH (diffie hellman key exchange) module" ON)
option(FEATPROD_ECDH_SUPPORTED "Enables ECDH (elliptic curve diffie-hellman) module" ON)
option(FEATPROD_ECDSA_SUPPORTED "Enables ECDSA (elliptic curve digital signature algorithm) module." ON)
option(FEATPROD_RSASSA_PSS_SUPPORTED "Enables RSASSA_PSS signature scheme module" ON)

#/* ENCRYPT - Authentication */
option(FEATPROD_STX_2FA_SUPPORTED "Enables 2FA authentication module" OFF)
option(FEATPROD_PBKDF1_SUPPORTED "Enables PBKDF1 authentication module" ON)
option(FEATPROD_PBKDF2_SUPPORTED "Enables PBKDF2 authentication module" OFF)
option(FEATPROD_SCRAM_SUPPORTED "Enables SCRAM authentication module " OFF)
option(FEATPROD_SIGN_SERVICE_SUPPORTED "Enables Signature Service module" ON)

option(FEATPROD_CKDF_SUPPORTED "Enables concatenation kdf module" ON)

#/* ENCRYPT - Legacy DO NOT USE */
option(FEATPROD_MD5_SUPPORTED "Enables MD5 (Message Digest)" ON)
option(FEATPROD_SHA1_SUPPORTED "Enables SHA1 (Secure Hash Algorithm 1 - 128 Bit)" ON)
option(FEATPROD_DES_SUPPORTED "Enables DES and 3DES ciphers" OFF)
option(FEATPROD_DAA_SUPPORTED "Enables DAA (Data Authentication Algorithm" OFF)
option(FEATPROD_CRYPTCTR_SUPPORTED "Enables CTR (Counter mode) module" OFF)
option(FEATPROD_CRYPTGCM_SUPPORTED "Enables GCM (Galois/Counter mode) module" OFF)

#/* FIRMWARE update */
option(FEATPROD_FWU_SUPPORTED "Enables sevenstax Firmware Update" OFF)

#/* RTOS */
option(FEATPROD_RTOS_DEMO "enables RTOS demo application" OFF)
option(FEATPROD_RTOS_SUPPORTED "enables RTOS wrapper" OFF)
option(FEATPROD_RTOS_TYPE_CMX "enables RTOS integration for CMX" OFF)
option(FEATPROD_RTOS_TYPE_EMBOS "enables RTOS integration for Segger embOS" OFF)
option(FEATPROD_RTOS_TYPE_SCIOPTA "enables RTOS integration for Sciopta" OFF)
option(FEATPROD_RTOS_TYPE_FREERTOS "enables RTOS integration for Sciopta" OFF)
option(FEATPROD_WRAPPER_HEAP_EMULATION "Enables special HEAP emulation in RTOS wrapper" OFF)

#/* V2G Protocol */
option(FEATPROD_V2G_SERIALIZER_SUPPORTED "Enables V2G Serializer" ON)
option(FEATPROD_V2G_PARSER_SUPPORTED "Enables V2G Parser" ON)
option(FEATPROD_XBAR_V2G_SUPPORTED "Enables XBAR V2G service module" OFF)

#/* V2G Mode */
option(FEATPROD_REFAPP_V2G_SUPPORTED "Enables V2G RefAPP" ON)
option(FEATPROD_V2G_PNC_SUPPORTED "Enables V2G PNC" ON)
option(FEATPROD_V2G_EVSE_SUPPORTED "Enables Electric Vehicle Supply Equipment (EVSE)" ON)
option(FEATPROD_V2G_EV_SUPPORTED "Enables Electric Vehicle (EV)" OFF)
option(FEATPROD_V2G_DIN_SUPPORTED "Enables DIN70121-2:2012 protocol" ON)
option(FEATPROD_V2G_ISO10_SUPPORTED "Enables ISO15118-2:2010 protocol" OFF)
option(FEATPROD_V2G_ISO_SUPPORTED "Enables ISO15118-2:2014 protocol" ON)
option(FEATPROD_V2G_ISO20_SUPPORTED "Enables ISO15118-20:2020 protocol" OFF)

#/* SECC */
option(FEATPROD_SECCDPS_SUPPORTED "SECC Discovery Protocol for EVSE" ON)
option(FEATPROD_SECCDP_SUPPORTED "SECC Discovery Protocol for EV" OFF)

#/* SLAC */
option(FEATPROD_SLAC_SUPPORTED "Enables SLAC module" ON)
option(FEATPROD_SLAC_SECURE_SUPPORTED "??" OFF)
option(FEATPROD_SLAC_SERV_SUPPORTED "Enables SLAC Service module " OFF)
option(FEATPROD_SLAC_MODE_EV_SUPPORTED     "enables EV mode for SLAC" OFF )
option(FEATPROD_SLAC_MODE_EVSE_SUPPORTED     "enables EVSE mode for SLAC" ON )

#/* PLC */
option(FEATPROD_PLC_SUPPORTED "Enables PLC modem module" ON)
option(FEATPROD_PLC_HL_BOOT_FROM_HOST     "Enables PLC HL boot from host" ON)
option(FEATPROD_PLC_MME_SUPPORTED         "Enables PLC MME support " ON)
option(FEATPROD_PLC_HL_MSE102X_SUPPORTED  "Enable PLC HL MSE102X driver" OFF)
option(FEATPROD_PLC_HL_QCA700X_SUPPORTED  "Enable PLC HL QCA700X driver" OFF)
option(FEATPROD_PLC_LL_MSE102X_SUPPORTED  "Enable PLC LL MSE102X driver" OFF)
option(FEATPROD_PLC_LL_QCA700X_SUPPORTED  "Enable PLC LL QCA700X driver" OFF)
option(FEATPROD_PLC_HL_CG5317_SUPPORTED   "Enable PLC HL CG5317 driver" ON)
option(FEATPROD_PLC_LL_CG5317_SUPPORTED   "Enable PLC LL CG5317 driver" OFF)
option(FEATPROD_SPI_SUPPORTED "Enables sevenstax SPI driver" OFF)

#/* special application */
option(FEATPROD_WSC_SUPPORTED "Enables WSC (Web Service Communication)" OFF)
option(FEATPROD_CAM_SUPPORTED "Enables camera application" OFF)
option(FEATPROD_TRGTHW_SUPPORTED "Enables default target abstraction laye" ON)
option(FEATPROD_MMI_SUPPORTED "Enables MMI library" OFF)
option(FEATPROD_NETCAT_SUPPORTED "Enable TCP UART Tunnel Applicatio" OFF)
option(FEATPROD_UDPMS_SUPPORTED "Enable UDP UART Tunnel Application" OFF)
option(FEATPROD_WEBCAT_SUPPORTED "Enable WEBSOCKET- UART Tunnel Application" OFF)
option(FEATPROD_MQTT_CLIENT_SUPPORTED "Enable MQTT Application" OFF)
option(FEATPROD_DATASTORAGE_SUPPORTED "Enable Datastorage- UART Tunnel Application" OFF)
option(FEATPROD_UPNP_SUPPORTED "Enable Basic UPNP Support" OFF)
option(FEATPROD_ETHBPS_SUPPORTED "Enables the ethernet bypass module" OFF)
option(FEATPROD_DATASTORAGE_SUPPORTED "Enable Datastorage- UART Tunnel Application " OFF)
option(FEATPROD_TOUCH_SUPPORTED "Support for Touch Controler " OFF)

#/* software tools and test */
option(FEATPROD_MTP_DBG_SUPPORTED "Enables DebugOuts via STX-MTP-Protocol" OFF)
option(FEATPROD_MTP_CNTRL_SUPPORTED "Enables Device Control via STX-MTP-Protocol" OFF)
option(FEATPROD_STXTOOLS_SUPPORTED "Enables different SEVENSTAX Tools" OFF)
option(FEATPROD_NTB_SUPPORTED "Activates SEVENSTAX Network Test Bench (Module test)" OFF)
option(FEATPROD_NTB_SIMSYSTIME_SUPPORTED "< Activates simulated system time. The continuing time in the Debug outs are not affected." OFF)
option(FEATPROD_CBCPERF_SUPPORTED "< Enable AES/CBC performance tests." OFF)

#/* 3rd Party modules */
option(FEATPROD_YAHOO_CLIENT_SUPPORTED "" OFF)
option(FEATPROD_TWITTER_CLIENT_SUPPORTED "" OFF)
option(FEATPROD_YOUTUBE_CLIENT_SUPPORTED "" OFF)
option(FEATPROD_FLICKR_CLIENT_SUPPORTED "" OFF)

#/* System load of Tick-Functions*/
option(FEATPROD_TICK_SYSLOAD_SUPPORTED "System load estimation (default 0" OFF)

