

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Mon Jan 18 22:14:07 2038
 */
/* Compiler settings for IWinHttpAutoProxySvc.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __IWinHttpAutoProxySvc_h_h__
#define __IWinHttpAutoProxySvc_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __IWinHttpAutoProxySvc_INTERFACE_DEFINED__
#define __IWinHttpAutoProxySvc_INTERFACE_DEFINED__

/* interface IWinHttpAutoProxySvc */
/* [helpstring][version][uuid] */ 

#define WINHTTP_AUTOPROXY_CONFIG_URL 0x00000002
#define WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY 0x00020000
typedef 
enum DNS_CONNECTION_POLICY_TAG
    {
        TAG_DNS_CONNECTION_POLICY_TAG_DEFAULT	= 0,
        TAG_DNS_CONNECTION_POLICY_TAG_CONNECTION_MANAGER	= ( TAG_DNS_CONNECTION_POLICY_TAG_DEFAULT + 1 ) ,
        TAG_DNS_CONNECTION_POLICY_TAG_WWWPT	= ( TAG_DNS_CONNECTION_POLICY_TAG_CONNECTION_MANAGER + 1 ) 
    } 	DNS_CONNECTION_POLICY_TAG;

typedef struct tagProxyResolveUrl
    {
    /* [string][unique] */ WCHAR *Url;
    /* [string][unique] */ WCHAR *Domain;
    /* [string][unique] */ WCHAR *Seperator;
    WORD Member4;
    WORD Member5;
    } 	tagProxyResolveUrl;

typedef struct WINHTTP_AUTOPROXY_OPTIONS
    {
    DWORD dwFlags;
    DWORD dwAutoDetectFlags;
    /* [string][unique] */ WCHAR *lpszAutoConfigUrl;
    /* [unique] */ DWORD *lpvReserved;
    DWORD dwReserved;
    DWORD fAutoLogonIfChallenged;
    } 	WINHTTP_AUTOPROXY_OPTIONS;

typedef struct WINHTTP_PROXY_RESULT_ENTRY
    {
    BOOL fProxy;
    BOOL fBypass;
    DWORD ProxyScheme;
    /* [string][unique] */ WCHAR *pwszProxy;
    WORD ProxyPort;
    } 	WINHTTP_PROXY_RESULT_ENTRY;

typedef struct WINHTTP_SESSION_OPTIONS
    {
    DWORD dwMaxTimeout;
    DWORD dwTimeout1;
    DWORD Member2;
    DWORD dwTimeout2;
    DWORD dwTimeout3;
    DWORD Member5;
    } 	WINHTTP_SESSION_OPTIONS;

typedef struct WINHTTP_PROXY_RESULT_EX
    {
    DWORD cEntries;
    /* [size_is] */ WINHTTP_PROXY_RESULT_ENTRY *pEntries;
    DWORD *hProxyDetectionHandle;
    DWORD dwProxyInterfaceAffinity;
    } 	WINHTTP_PROXY_RESULT_EX;

typedef struct WINHTTP_PROXY_NETWORKING_KEY
    {
    BYTE pbBuffer[ 128 ];
    } 	WINHTTP_PROXY_NETWORKING_KEY;

typedef struct WINHTTP_PROXY_SETTINGS
    {
    DWORD dwStructSize;
    DWORD dwFlags;
    DWORD dwCurrentSettingsVersion;
    /* [string][unique] */ WCHAR *pwszConnectionName;
    /* [string][unique] */ WCHAR *pwszProxy;
    /* [string][unique] */ WCHAR *pwszProxyBypass;
    /* [string][unique] */ WCHAR *pwszAutoconfigUrl;
    /* [string][unique] */ WCHAR *pwszAutoconfigSecondaryUrl;
    DWORD dwAutoDiscoveryFlags;
    /* [string][unique] */ WCHAR *pwszLastKnownGoodAutoConfigUrl;
    DWORD dwAutoconfigReloadDelayMins;
    FILETIME ftLastKnownDetectTime;
    DWORD dwDetectedInterfaceIpCount;
    /* [size_is] */ DWORD *pdwDetectedInterfaceIp;
    DWORD cNetworkKeys;
    /* [size_is] */ WINHTTP_PROXY_NETWORKING_KEY *pNetworkKeys;
    } 	WINHTTP_PROXY_SETTINGS;

typedef struct DNS_CONNECTION_IFINDEX_ENTRY
    {
    /* [string][unique] */ WCHAR *pwszConnectionName;
    DWORD dwIfIndex;
    } 	DNS_CONNECTION_IFINDEX_ENTRY;

typedef struct DNS_CONNECTION_IFINDEX_LIST
    {
    /* [size_is] */ DNS_CONNECTION_IFINDEX_ENTRY *pConnectionIfIndexEntries;
    DWORD nEntries;
    } 	DNS_CONNECTION_IFINDEX_LIST;

typedef struct DNS_CONNECTION_POLICY_ENTRY
    {
    /* [string][unique] */ WCHAR *pwszHost;
    /* [string][unique] */ WCHAR *pwszAppId;
    DWORD cbAppSid;
    /* [size_is] */ BYTE *pbAppSid;
    DWORD nConnections;
    /* [unique] */ WCHAR **ppwszConnections;
    DWORD dwPolicyEntryFlags;
    } 	DNS_CONNECTION_POLICY_ENTRY;

typedef struct DNS_CONNECTION_POLICY_ENTRY_LIST
    {
    /* [size_is] */ DNS_CONNECTION_POLICY_ENTRY *pPolicyEntries;
    DWORD nEntries;
    } 	DNS_CONNECTION_POLICY_ENTRY_LIST;

/* [async] */ void  GetProxyForUrl( 
    /* [in] */ PRPC_ASYNC_STATE GetProxyForUrl_AsyncHandle,
    handle_t hRpcBinding,
    /* [in] */ tagProxyResolveUrl *ProxyResolveUrl,
    /* [in] */ WINHTTP_AUTOPROXY_OPTIONS *AutoProxyOptions,
    /* [in] */ WINHTTP_SESSION_OPTIONS *SessionOptions,
    /* [in] */ DWORD DataLength,
    /* [size_is][unique][in] */ BYTE *ByteArray,
    /* [out] */ DWORD *Int,
    /* [out] */ WINHTTP_PROXY_RESULT_EX *ProxyResultEx,
    /* [system_handle][out] */ HANDLE *NameResTrkRecordHandle,
    /* [out] */ DWORD *WinHttpStatusCode);

HRESULT ResetAutoProxy( 
    handle_t hRpcBinding,
    /* [in] */ DWORD dwFlags);

HRESULT SaveProxyCredentials( 
    handle_t hRpcBinding,
    /* [in] */ DWORD CredentialFlag,
    /* [string][in] */ WCHAR *TargetName,
    /* [string][in] */ WCHAR *UserName,
    /* [string][in] */ WCHAR *CredentialBlob);

HRESULT StoreSavedProxyCredentialsForCurrentUser( 
    handle_t hRpcBinding,
    /* [in] */ DWORD CredentialFlag,
    /* [string][in] */ WCHAR *TargetName,
    /* [out] */ DWORD *StatusCode);

HRESULT DeleteSavedProxyCredentials( 
    handle_t hRpcBinding,
    /* [in] */ wchar_t *TargetName);

HRESULT ReindicateAllProxies( 
    /* [in] */ handle_t IDL_handle);

HRESULT ReadProxySettings( 
    handle_t hRpcBinding,
    /* [string][unique][in] */ WCHAR *ConnectionName,
    /* [in] */ DWORD dwFlags,
    /* [in] */ DWORD p4,
    /* [out] */ DWORD *p5,
    /* [out] */ DWORD *p6,
    /* [out] */ WINHTTP_PROXY_SETTINGS *ProxySettings);

HRESULT WriteProxySettings( 
    handle_t hRpcBinding,
    /* [in] */ BOOL fForceUpdate,
    /* [in] */ WINHTTP_PROXY_SETTINGS *ProxySettings);

HRESULT ConnectionUpdateIfIndexTable( 
    handle_t hRpcBinding,
    /* [in] */ DNS_CONNECTION_IFINDEX_LIST *pConnectionIfIndexEntries);

HRESULT ConnectionSetPolicyEntries( 
    handle_t hRpcBinding,
    /* [in] */ DNS_CONNECTION_POLICY_TAG PolicyEntryTag,
    /* [in] */ DNS_CONNECTION_POLICY_ENTRY_LIST *pPolicyEntryList);

HRESULT ConnectionDeletePolicyEntries( 
    handle_t hRpcBinding,
    /* [in] */ DNS_CONNECTION_POLICY_TAG PolicyEntryTag);



extern RPC_IF_HANDLE IWinHttpAutoProxySvc_v5_1_c_ifspec;
extern RPC_IF_HANDLE IWinHttpAutoProxySvc_v5_1_s_ifspec;
#endif /* __IWinHttpAutoProxySvc_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


