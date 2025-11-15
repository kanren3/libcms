#ifndef _LIBCMS_H_
#define _LIBCMS_H_

EXTERN_C_START

#define MBEDTLS_OID_PKCS7                            MBEDTLS_OID_PKCS "\x07"
#define MBEDTLS_OID_PKCS7_DATA                       MBEDTLS_OID_PKCS7 "\x01"
#define MBEDTLS_OID_PKCS7_SIGNED_DATA                MBEDTLS_OID_PKCS7 "\x02"
#define MBEDTLS_OID_PKCS7_ENVELOPED_DATA             MBEDTLS_OID_PKCS7 "\x03"
#define MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA  MBEDTLS_OID_PKCS7 "\x04"
#define MBEDTLS_OID_PKCS7_DIGESTED_DATA              MBEDTLS_OID_PKCS7 "\x05"
#define MBEDTLS_OID_PKCS7_ENCRYPTED_DATA             MBEDTLS_OID_PKCS7 "\x06"

typedef mbedtls_x509_crt CMS_PKCS7_CERTIFICATE_SET;
typedef mbedtls_x509_crl CMS_PKCS7_CRLS;

typedef CMS_PKCS7_CERTIFICATE_SET *PCMS_PKCS7_CERTIFICATE_SET;
typedef CMS_PKCS7_CRLS *PCMS_PKCS7_CRLS;

typedef struct _CMS_BLOB {
    PUINT8 Data;
    SIZE_T Length;
} CMS_BLOB, *PCMS_BLOB;

typedef struct _CMS_PKCS7_ATTRIBUTE_VALUE {
    struct _CMS_PKCS7_ATTRIBUTE_VALUE *Next;
    CMS_BLOB Blob;
} CMS_PKCS7_ATTRIBUTE_VALUE, *PCMS_PKCS7_ATTRIBUTE_VALUE;

typedef struct _CMS_PKCS7_ATTRIBUTE {
    struct _CMS_PKCS7_ATTRIBUTE *Next;
    CMS_BLOB AttributeTypeOid;
    PCMS_PKCS7_ATTRIBUTE_VALUE Values;
} CMS_PKCS7_ATTRIBUTE, *PCMS_PKCS7_ATTRIBUTE;

typedef struct _CMS_PKCS7_SIGNER_INFO {
    struct _CMS_PKCS7_SIGNER_INFO *Next;
    INT Version;
    CMS_BLOB IssuerAndSerialNumber;
    CMS_BLOB DigestAlgorithm;
    PCMS_PKCS7_ATTRIBUTE SignedAttributes;
    CMS_BLOB SignatureAlgorithm;
    CMS_BLOB Signature;
    PCMS_PKCS7_ATTRIBUTE UnsignedAttributes;
} CMS_PKCS7_SIGNER_INFO, *PCMS_PKCS7_SIGNER_INFO;

typedef struct _CMS_PKCS7_SIGNED_DATA {
    INT Version;
    CMS_BLOB DigestAlgorithms;
    CMS_BLOB EncapContentInfo;
    CMS_PKCS7_CERTIFICATE_SET Certificates;
    CMS_PKCS7_CRLS CertificateRevocationLists;
    PCMS_PKCS7_SIGNER_INFO SignerInfos;
} CMS_PKCS7_SIGNED_DATA, *PCMS_PKCS7_SIGNED_DATA;

typedef struct _CMS_PKCS7_DER {
    CMS_BLOB ContentTypeOid;
    CMS_PKCS7_SIGNED_DATA SignedData;
} CMS_PKCS7_DER, *PCMS_PKCS7_DER;

FORCEINLINE
PVOID
CmsAllocatePoolZero (
    _In_ SIZE_T NumberOfBytes
)
{
    PVOID Pointer;

    Pointer = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, 'cms');

    if (NULL != Pointer) {
        RtlZeroBytes(Pointer, NumberOfBytes);
    }

    return Pointer;
}

FORCEINLINE
VOID
CmsFreePool (
    _In_ PVOID Pointer
)
{
    ExFreePoolWithTag(Pointer, 'cms');
}

EXTERN_C_END

#endif
