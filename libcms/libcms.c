#include <mbedtls/mbedtls_config.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

#include "libcms.h"

#define MBEDTLS_OID_PKCS7                            MBEDTLS_OID_PKCS  "\x07"
#define MBEDTLS_OID_PKCS7_DATA                       MBEDTLS_OID_PKCS7 "\x01"
#define MBEDTLS_OID_PKCS7_SIGNED_DATA                MBEDTLS_OID_PKCS7 "\x02"
#define MBEDTLS_OID_PKCS7_ENVELOPED_DATA             MBEDTLS_OID_PKCS7 "\x03"
#define MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA  MBEDTLS_OID_PKCS7 "\x04"
#define MBEDTLS_OID_PKCS7_DIGESTED_DATA              MBEDTLS_OID_PKCS7 "\x05"
#define MBEDTLS_OID_PKCS7_ENCRYPTED_DATA             MBEDTLS_OID_PKCS7 "\x06"

typedef struct _CMS_BLOB {
    PUINT8 Data;
    SIZE_T Length;
} CMS_BLOB, *PCMS_BLOB;

typedef struct _CMS_ATTRIBUTE_VALUE {
    CMS_BLOB Blob;
    struct _CMS_ATTRIBUTE_VALUE *Next;
} CMS_ATTRIBUTE_VALUE, *PCMS_ATTRIBUTE_VALUE;

typedef struct _CMS_ATTRIBUTE {
    CMS_BLOB AttributeTypeOid;
    PCMS_ATTRIBUTE_VALUE Values;
    struct _CMS_ATTRIBUTE *Next;
} CMS_ATTRIBUTE, *PCMS_ATTRIBUTE;

typedef struct _CMS_SIGNER_INFO {
    INT32 Version;
    CMS_BLOB IssuerAndSerialNumber;
    CMS_BLOB DigestAlgorithm;
    PCMS_ATTRIBUTE SignedAttributes;
    CMS_BLOB SignatureAlgorithm;
    CMS_BLOB Signature;
    PCMS_ATTRIBUTE UnsignedAttributes;
    struct _CMS_SIGNER_INFO *Next;
} CMS_SIGNER_INFO, *PCMS_SIGNER_INFO;

typedef struct _CMS_ENCAPSULATED_CONTENT_INFO {
    CMS_BLOB ContentTypeOid;
    CMS_BLOB Content;
} CMS_ENCAPSULATED_CONTENT_INFO, *PCMS_ENCAPSULATED_CONTENT_INFO;

typedef struct _CMS_SIGNED_DATA {
    INT32 Version;
    CMS_BLOB DigestAlgorithms;
    CMS_ENCAPSULATED_CONTENT_INFO EncapsulatedContentInfo;
    mbedtls_x509_crt Certificates;
    mbedtls_x509_crl CertificateRevocationLists;
    PCMS_SIGNER_INFO SignerInfos;
} CMS_SIGNED_DATA, *PCMS_SIGNED_DATA;

typedef struct _CMS_PKCS7_DER {
    CMS_BLOB ContentTypeOid;
    CMS_SIGNED_DATA SignedData;
} CMS_PKCS7_DER, *PCMS_PKCS7_DER;

FORCEINLINE
PVOID
CmsAllocatePoolZero (
    _In_ SIZE_T NumberOfBytes
)
{
    PVOID Pointer;

    Pointer = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, 'lsmc');

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
    ExFreePoolWithTag(Pointer, 'lsmc');
}

VOID
CmsDbgPrint (
    _In_ PCSTR Format,
    _In_ ...
)
{
    va_list ArgList1;
    va_list ArgList2;
    int CountBytes;
    SIZE_T NumberOfBytes;
    SIZE_T NumberOfChunks;
    SIZE_T Remaining;
    SIZE_T DbgPrintLengthMax = 511;
    SIZE_T Index;
    PCHAR Buffer = NULL;
    ANSI_STRING String;

    va_start(ArgList1, Format);
    va_copy(ArgList2, ArgList1);

    CountBytes = _vsnprintf(NULL, 0, Format, ArgList1);

    if (CountBytes <= 0) {
        goto Cleanup;
    }

    NumberOfBytes = CountBytes;
    Buffer = CmsAllocatePoolZero(NumberOfBytes);

    if (NULL == Buffer) {
        goto Cleanup;
    }
    
    if (_vsnprintf(Buffer, NumberOfBytes, Format, ArgList2) <= 0) {
        goto Cleanup;
    }
    
    NumberOfChunks = NumberOfBytes / DbgPrintLengthMax;
    Remaining = NumberOfBytes % DbgPrintLengthMax;

    for (Index = 0; Index < NumberOfChunks; Index++) {
        String.Buffer = Buffer + Index * DbgPrintLengthMax;
        String.Length = String.MaximumLength = DbgPrintLengthMax;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%Z", &String);
    }

    if (0 != Remaining) {
        String.Buffer = Buffer + NumberOfChunks * DbgPrintLengthMax;
        String.Length = String.MaximumLength = Remaining;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%Z", &String);
    }

Cleanup:

    if (NULL != Buffer) {
        CmsFreePool(Buffer);
    }

    va_end(ArgList1);
    va_end(ArgList2);
}

NTSTATUS
CmsParseAttributeValue (
    _In_ PUINT8 AttributeValueData,
    _In_ SIZE_T AttributeValueLength,
    _Out_ PCMS_ATTRIBUTE_VALUE *AttributeValue
)
{
    PCMS_ATTRIBUTE_VALUE NewValue;

    NewValue = CmsAllocatePoolZero(sizeof(CMS_ATTRIBUTE_VALUE));

    if (NULL == NewValue) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    NewValue->Blob.Data = AttributeValueData;
    NewValue->Blob.Length = AttributeValueLength;

    *AttributeValue = NewValue;

    return STATUS_SUCCESS;
}

VOID
CmsFreeAttributeValues (
    _In_ PCMS_ATTRIBUTE_VALUE AttributeValues
)
{
    PCMS_ATTRIBUTE_VALUE Current;
    PCMS_ATTRIBUTE_VALUE Previous;

    if (NULL != AttributeValues) {
        Current = AttributeValues;

        while (Current != NULL) {
            Previous = Current;
            Current = Current->Next;

            CmsFreePool(Previous);
        }
    }
}

NTSTATUS
CmsParseAttribute (
    _In_ PUINT8 AttributeData,
    _In_ SIZE_T AttributeLength,
    _Out_ PCMS_ATTRIBUTE *Attribute
)
{
    NTSTATUS Status;
    INT Result;
    PUINT8 Buffer;
    PUINT8 Pointer;
    PUINT8 AttributeEnd;
    PUINT8 AttributeValuesEnd;
    SIZE_T Length;
    PCMS_ATTRIBUTE NewAttribute;
    PCMS_ATTRIBUTE_VALUE AttributeValue;
    PCMS_ATTRIBUTE_VALUE Node;

    Pointer = AttributeData;
    AttributeEnd = AttributeData + AttributeLength;

    NewAttribute = CmsAllocatePoolZero(sizeof(CMS_ATTRIBUTE));

    if (NULL == NewAttribute) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, AttributeEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewAttribute->AttributeTypeOid.Data = Pointer;
    NewAttribute->AttributeTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, AttributeEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    AttributeValuesEnd = Pointer + Length;

    while (TRUE) {
        Buffer = Pointer;
        Result = mbedtls_asn1_get_tag(&Pointer, AttributeValuesEnd, &Length, Buffer[0]);

        if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
            break;
        }

        if (0 != Result) {
            Status = STATUS_INVALID_IMAGE_HASH;
            goto Cleanup;
        }

        Status = CmsParseAttributeValue(Buffer, Pointer + Length - Buffer, &AttributeValue);

        if (FALSE == NT_SUCCESS(Status)) {
            goto Cleanup;
        }
        
        if (NULL == NewAttribute->Values) {
            NewAttribute->Values = AttributeValue;
        }
        else {
            Node = NewAttribute->Values;

            while (Node->Next != NULL) {
                Node = Node->Next;
            }

            Node->Next = AttributeValue;
        }

        Pointer += Length;
    }

    *Attribute = NewAttribute;
    
    return STATUS_SUCCESS;

Cleanup:

    if (NULL != NewAttribute) {
        CmsFreeAttributeValues(NewAttribute->Values);
        CmsFreePool(NewAttribute);
    }

    return Status;
}

VOID
CmsFreeAttributes (
    _In_ PCMS_ATTRIBUTE Attributes
)
{
    PCMS_ATTRIBUTE Current;
    PCMS_ATTRIBUTE Previous;

    if (NULL != Attributes) {
        Current = Attributes;

        while (Current != NULL) {
            Previous = Current;
            Current = Current->Next;

            CmsFreeAttributeValues(Previous->Values);
            CmsFreePool(Previous);
        }
    }
}

NTSTATUS
CmsParseSignerInfo (
    _In_ PUINT8 SignerInfoData,
    _In_ SIZE_T SignerInfoLength,
    _Out_ PCMS_SIGNER_INFO *SignerInfo
)
{
    NTSTATUS Status;
    INT Result;
    PUINT8 Pointer;
    PUINT8 SignerInfoEnd;
    PUINT8 SignedAttributesEnd;
    PUINT8 UnsignedAttributesEnd;
    SIZE_T Length;
    PCMS_SIGNER_INFO NewSignerInfo;
    PCMS_ATTRIBUTE Attribute;
    PCMS_ATTRIBUTE Node;

    Pointer = SignerInfoData;
    SignerInfoEnd = SignerInfoData + SignerInfoLength;

    NewSignerInfo = CmsAllocatePoolZero(sizeof(CMS_SIGNER_INFO));

    if (NULL == NewSignerInfo) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    if (mbedtls_asn1_get_int(&Pointer, SignerInfoEnd, &NewSignerInfo->Version) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    if (NewSignerInfo->Version != 1) {
        Status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewSignerInfo->IssuerAndSerialNumber.Data = Pointer;
    NewSignerInfo->IssuerAndSerialNumber.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewSignerInfo->DigestAlgorithm.Data = Pointer;
    NewSignerInfo->DigestAlgorithm.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
        SignedAttributesEnd = Pointer + Length;

        while (TRUE) {
            Result = mbedtls_asn1_get_tag(&Pointer, SignedAttributesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }

            Status = CmsParseAttribute(Pointer, Length, &Attribute);

            if (FALSE == NT_SUCCESS(Status)) {
                goto Cleanup;
            }

            if (NULL == NewSignerInfo->SignedAttributes) {
                NewSignerInfo->SignedAttributes = Attribute;
            }
            else {
                Node = NewSignerInfo->SignedAttributes;

                while (Node->Next != NULL) {
                    Node = Node->Next;
                }

                Node->Next = Attribute;
            }

            Pointer += Length;
        }
    }

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewSignerInfo->SignatureAlgorithm.Data = Pointer;
    NewSignerInfo->SignatureAlgorithm.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewSignerInfo->Signature.Data = Pointer;
    NewSignerInfo->Signature.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1) == 0) {
        UnsignedAttributesEnd = Pointer + Length;

        while (TRUE) {
            Result = mbedtls_asn1_get_tag(&Pointer, UnsignedAttributesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }

            Status = CmsParseAttribute(Pointer, Length, &Attribute);

            if (FALSE == NT_SUCCESS(Status)) {
                goto Cleanup;
            }

            if (NULL == NewSignerInfo->UnsignedAttributes) {
                NewSignerInfo->UnsignedAttributes = Attribute;
            }
            else {
                Node = NewSignerInfo->UnsignedAttributes;

                while (Node->Next != NULL) {
                    Node = Node->Next;
                }

                Node->Next = Attribute;
            }

            Pointer += Length;
        }
    }

    *SignerInfo = NewSignerInfo;

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != NewSignerInfo) {
        CmsFreeAttributes(NewSignerInfo->SignedAttributes);
        CmsFreeAttributes(NewSignerInfo->UnsignedAttributes);
        CmsFreePool(NewSignerInfo);
    }

    return Status;
}

VOID
CmsFreeSignerInfos (
    _In_ PCMS_SIGNER_INFO SignerInfos
)
{
    PCMS_SIGNER_INFO Current;
    PCMS_SIGNER_INFO Previous;

    if (NULL != SignerInfos) {
        Current = SignerInfos;

        while (Current != NULL) {
            Previous = Current;
            Current = Current->Next;

            CmsFreeAttributes(Previous->SignedAttributes);
            CmsFreeAttributes(Previous->UnsignedAttributes);
            CmsFreePool(Previous);
        }
    }
}

NTSTATUS
CmsParsePkcs7Der (
    _In_ PUINT8 Pkcs7Data,
    _In_ SIZE_T Pkcs7Length,
    _Out_ PCMS_PKCS7_DER *Pkcs7Der
)
{
    NTSTATUS Status;
    INT Result;
    PUINT8 Buffer;
    PUINT8 Pointer;
    PUINT8 Pkcs7End;
    PUINT8 ContentInfoEnd;
    PUINT8 ContentEnd;
    PUINT8 EncapsulatedContentInfoEnd;
    PUINT8 CertificatesEnd;
    PUINT8 SignerInfosEnd;
    PCMS_PKCS7_DER NewPkcs7Der;
    PCMS_SIGNER_INFO SignerInfos;
    PCMS_SIGNER_INFO Node;
    SIZE_T Length;

    Pointer = Pkcs7Data;
    Pkcs7End = Pkcs7Data + Pkcs7Length;

    NewPkcs7Der = CmsAllocatePoolZero(sizeof(CMS_PKCS7_DER));

    if (NULL == NewPkcs7Der) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    mbedtls_x509_crt_init(&NewPkcs7Der->SignedData.Certificates);
    mbedtls_x509_crl_init(&NewPkcs7Der->SignedData.CertificateRevocationLists);

    if (mbedtls_asn1_get_tag(&Pointer, Pkcs7End, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    ContentInfoEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentInfoEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    if (Length != sizeof(MBEDTLS_OID_PKCS7_SIGNED_DATA) - 1) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    if (memcmp(Pointer, MBEDTLS_OID_PKCS7_SIGNED_DATA, sizeof(MBEDTLS_OID_PKCS7_SIGNED_DATA) - 1) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewPkcs7Der->ContentTypeOid.Data = Pointer;
    NewPkcs7Der->ContentTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    ContentEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    if (mbedtls_asn1_get_int(&Pointer, ContentEnd, &NewPkcs7Der->SignedData.Version) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewPkcs7Der->SignedData.DigestAlgorithms.Data = Pointer;
    NewPkcs7Der->SignedData.DigestAlgorithms.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    EncapsulatedContentInfoEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, EncapsulatedContentInfoEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    NewPkcs7Der->SignedData.EncapsulatedContentInfo.ContentTypeOid.Data = Pointer;
    NewPkcs7Der->SignedData.EncapsulatedContentInfo.ContentTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, EncapsulatedContentInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
        NewPkcs7Der->SignedData.EncapsulatedContentInfo.Content.Data = Pointer;
        NewPkcs7Der->SignedData.EncapsulatedContentInfo.Content.Length = Length;
        Pointer += Length;
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
        CertificatesEnd = Pointer + Length;

        while (TRUE) {
            Buffer = Pointer;
            Result = mbedtls_asn1_get_tag(&Pointer, CertificatesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }

            Pointer += Length;
            Result = mbedtls_x509_crt_parse_der(&NewPkcs7Der->SignedData.Certificates, Buffer, Pointer - Buffer);

            if (MBEDTLS_ERR_X509_ALLOC_FAILED == Result) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }
        }
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1) == 0) {
        CertificatesEnd = Pointer + Length;

        while (TRUE) {
            Buffer = Pointer;
            Result = mbedtls_asn1_get_tag(&Pointer, CertificatesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }

            Pointer += Length;
            Result = mbedtls_x509_crl_parse_der(&NewPkcs7Der->SignedData.CertificateRevocationLists, Buffer, Pointer - Buffer);

            if (MBEDTLS_ERR_X509_ALLOC_FAILED == Result) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }

            if (0 != Result) {
                Status = STATUS_INVALID_IMAGE_HASH;
                goto Cleanup;
            }
        }
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        Status = STATUS_INVALID_IMAGE_HASH;
        goto Cleanup;
    }

    SignerInfosEnd = Pointer + Length;

    while (TRUE) {
        Result = mbedtls_asn1_get_tag(&Pointer, SignerInfosEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

        if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
            break;
        }

        if (0 != Result) {
            Status = STATUS_INVALID_IMAGE_HASH;
            goto Cleanup;
        }

        Status = CmsParseSignerInfo(Pointer, Length, &SignerInfos);
        
        if (FALSE == NT_SUCCESS(Status)) {
            goto Cleanup;
        }

        if (NULL == NewPkcs7Der->SignedData.SignerInfos) {
            NewPkcs7Der->SignedData.SignerInfos = SignerInfos;
        }
        else {
            Node = NewPkcs7Der->SignedData.SignerInfos;

            while (Node->Next != NULL) {
                Node = Node->Next;
            }

            Node->Next = SignerInfos;
        }

        Pointer += Length;
    }

    *Pkcs7Der = NewPkcs7Der;

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != NewPkcs7Der) {
        mbedtls_x509_crt_free(&NewPkcs7Der->SignedData.Certificates);
        mbedtls_x509_crl_free(&NewPkcs7Der->SignedData.CertificateRevocationLists);

        CmsFreeSignerInfos(NewPkcs7Der->SignedData.SignerInfos);
        CmsFreePool(NewPkcs7Der);
    }

    return Status;
}

VOID
CmsFreePkcs7Der (
    _Inout_ PCMS_PKCS7_DER Pkcs7Der
)
{
    if (NULL != Pkcs7Der) {
        mbedtls_x509_crt_free(&Pkcs7Der->SignedData.Certificates);
        mbedtls_x509_crl_free(&Pkcs7Der->SignedData.CertificateRevocationLists);

        CmsFreeSignerInfos(Pkcs7Der->SignedData.SignerInfos);
        CmsFreePool(Pkcs7Der);
    }
}

int mbedtls_x509_crt_hash(char *buf, size_t size, const char *prefix, const mbedtls_x509_crt *crt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    char *p;
    unsigned char hash[64];

    p = buf;
    n = size;

    ret = mbedtls_sha1(crt->raw.p, crt->raw.len, hash);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = _snprintf(p, n, "%sthumbprint (sha1) : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;

    for (size_t i = 0; i < 20; i++) {
        ret = _snprintf(p, n, "%02X", hash[i]);
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    ret = mbedtls_sha1(crt->tbs.p, crt->tbs.len, hash);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = _snprintf(p, n, "\n%stbs hash (sha1)   : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;

    for (size_t i = 0; i < 20; i++) {
        ret = _snprintf(p, n, "%02X", hash[i]);
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    ret = mbedtls_sha256(crt->tbs.p, crt->tbs.len, hash, 0);
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = _snprintf(p, n, "\n%stbs hash (sha256) : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;

    for (size_t i = 0; i < 32; i++) {
        ret = _snprintf(p, n, "%02X", hash[i]);
        MBEDTLS_X509_SAFE_SNPRINTF;
    }

    ret = _snprintf(p, n, "\n");
    MBEDTLS_X509_SAFE_SNPRINTF;

    return (int)(size - n);
}

VOID
CmsPrintCertificateInfo (
    _In_ mbedtls_x509_crt *Certificate
)
{
    PCHAR Buffer;

    Buffer = CmsAllocatePoolZero(0x1001);

    if (NULL != Buffer) {
        CmsDbgPrint("============Certificate Information============\n");
        
        mbedtls_x509_crt_info(Buffer, 0x1000, "", Certificate);
        CmsDbgPrint("%s", Buffer);

        mbedtls_x509_crt_hash(Buffer, 0x1000, "", Certificate);
        CmsDbgPrint("%s", Buffer);

        CmsDbgPrint("===============================================\n\n");
        CmsFreePool(Buffer);
    }
}

VOID
CmsRecursiveParsePkcs7Der (
    _In_ PUINT8 Pkcs7Data,
    _In_ SIZE_T Pkcs7Length
)
{
    NTSTATUS Status;
    PCMS_PKCS7_DER Pkcs7Der;
    mbedtls_x509_crt *Certificate;
    PCMS_ATTRIBUTE UnsignedAttribute;
    PCMS_ATTRIBUTE_VALUE UnsignedAttributeValue;

    Status = CmsParsePkcs7Der(Pkcs7Data, Pkcs7Length, &Pkcs7Der);

    if (FALSE != NT_SUCCESS(Status)) {
        Certificate = &Pkcs7Der->SignedData.Certificates;

        while (NULL != Certificate && NULL != Certificate->raw.p) {
            CmsPrintCertificateInfo(Certificate);
            Certificate = Certificate->next;
        }

        if (NULL != Pkcs7Der->SignedData.SignerInfos) {
            UnsignedAttribute = Pkcs7Der->SignedData.SignerInfos->UnsignedAttributes;

            while (NULL != UnsignedAttribute) {
                UnsignedAttributeValue = UnsignedAttribute->Values;

                while (NULL != UnsignedAttributeValue) {
                    CmsRecursiveParsePkcs7Der(UnsignedAttributeValue->Blob.Data, UnsignedAttributeValue->Blob.Length);
                    UnsignedAttributeValue = UnsignedAttributeValue->Next;
                }

                UnsignedAttribute = UnsignedAttribute->Next;
            }
        }

        CmsFreePkcs7Der(Pkcs7Der);
    }
}

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
);

#define WIN_CERT_REVISION_1_0               (0x0100)
#define WIN_CERT_REVISION_2_0               (0x0200)

#define WIN_CERT_TYPE_X509                  (0x0001)
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      (0x0002)
#define WIN_CERT_TYPE_RESERVED_1            (0x0003)
#define WIN_CERT_TYPE_TS_STACK_SIGNED       (0x0004)

typedef struct _CMS_WIN_CERTIFICATE {
    UINT32 Length;
    UINT16 Revision;
    UINT16 CertificateType;
    UINT8 Certificate[1];
} CMS_WIN_CERTIFICATE, *PCMS_WIN_CERTIFICATE;

NTSTATUS
CmsTestPausePkcs7Data (
    VOID
)
{
    NTSTATUS Status;
    UNICODE_STRING ImageFullPath;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle = NULL;
    FILE_STANDARD_INFORMATION StandardInformation;
    PUINT8 Buffer = NULL;
    PCMS_WIN_CERTIFICATE Certificate;
    UINT32 SecurityDataSize;
    UINT32 EncodedSignedSize;
    PUINT8 EncodedSignedData;

    RtlInitUnicodeString(&ImageFullPath, L"\\??\\C:\\test.sys");

    InitializeObjectAttributes(&ObjectAttributes,
                               &ImageFullPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    Status = ZwCreateFile(&FileHandle,
                          FILE_GENERIC_READ,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &StandardInformation,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (StandardInformation.EndOfFile.QuadPart > ULONG_MAX) {
        Status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    Buffer = CmsAllocatePoolZero(StandardInformation.EndOfFile.LowPart);

    if (NULL == Buffer) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Status = ZwReadFile(FileHandle,
                        NULL,
                        NULL,
                        NULL,
                        &IoStatusBlock,
                        Buffer,
                        StandardInformation.EndOfFile.LowPart,
                        NULL,
                        NULL);

    if (FALSE == NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Certificate = RtlImageDirectoryEntryToData(Buffer,
                                               TRUE,
                                               IMAGE_DIRECTORY_ENTRY_SECURITY,
                                               &SecurityDataSize);

    if (NULL == Certificate) {
        Status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    if (WIN_CERT_TYPE_PKCS_SIGNED_DATA != Certificate->CertificateType) {
        Status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    EncodedSignedSize = Certificate->Length - FIELD_OFFSET(CMS_WIN_CERTIFICATE, Certificate);
    EncodedSignedData = Certificate->Certificate;

    if ((EncodedSignedData + EncodedSignedSize) > (Buffer + StandardInformation.EndOfFile.LowPart)) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    CmsRecursiveParsePkcs7Der(EncodedSignedData, EncodedSignedSize);

    CmsFreePool(Buffer);
    ZwClose(FileHandle);

    return STATUS_SUCCESS;

Cleanup:

    if (NULL != Buffer) {
        CmsFreePool(Buffer);
    }

    if (NULL != FileHandle) {
        ZwClose(FileHandle);
    }

    return Status;
}

VOID
NTAPI
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
)
{

}

NTSTATUS
NTAPI
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    UNICODE_STRING ImagePath;

    DriverObject->DriverUnload = DriverUnload;

    Status = CmsTestPausePkcs7Data();
    CmsDbgPrint("CmsTestPausePkcs7Data = %08X\n", Status);

    Status = STATUS_UNSUCCESSFUL;

    return Status;
}
