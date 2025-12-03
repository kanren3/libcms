#include <mbedtls/mbedtls_config.h>
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

typedef struct mbedtls_x509_crt CMS_X509_CERTIFICATE;
typedef struct mbedtls_x509_crl CMS_X509_CRL;

typedef CMS_X509_CERTIFICATE *PCMS_X509_CERTIFICATE;
typedef CMS_X509_CRL *PCMS_X509_CRL;

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
    CMS_X509_CERTIFICATE Certificates;
    CMS_X509_CRL CertificateRevocationLists;
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

PCMS_ATTRIBUTE_VALUE
CmsParseAttributeValue (
    _In_ PUINT8 AttributeValueData,
    _In_ SIZE_T AttributeValueLength
)
{
    PCMS_ATTRIBUTE_VALUE AttributeValue;

    AttributeValue = CmsAllocatePoolZero(sizeof(CMS_ATTRIBUTE_VALUE));

    if (NULL == AttributeValue) {
        return NULL;
    }

    AttributeValue->Blob.Data = AttributeValueData;
    AttributeValue->Blob.Length = AttributeValueLength;

    return AttributeValue;
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

PCMS_ATTRIBUTE
CmsParseAttribute (
    _In_ PUINT8 AttributeData,
    _In_ SIZE_T AttributeLength
)
{
    INT Result;
    PUINT8 Buffer;
    PUINT8 Pointer;
    PUINT8 AttributeEnd;
    PUINT8 AttributeValuesEnd;
    SIZE_T Length;
    PCMS_ATTRIBUTE Attribute;
    PCMS_ATTRIBUTE_VALUE AttributeValue;
    PCMS_ATTRIBUTE_VALUE Node;

    Pointer = AttributeData;
    AttributeEnd = AttributeData + AttributeLength;

    Attribute = CmsAllocatePoolZero(sizeof(CMS_ATTRIBUTE));

    if (NULL == Attribute) {
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, AttributeEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        goto Cleanup;
    }

    Attribute->AttributeTypeOid.Data = Pointer;
    Attribute->AttributeTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, AttributeEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
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
            goto Cleanup;
        }

        AttributeValue = CmsParseAttributeValue(Buffer, Pointer + Length - Buffer);

        if (NULL == AttributeValue) {
            goto Cleanup;
        }

        if (NULL == Attribute->Values) {
            Attribute->Values = AttributeValue;
        }
        else {
            Node = Attribute->Values;

            while (Node->Next != NULL) {
                Node = Node->Next;
            }

            Node->Next = AttributeValue;
        }

        Pointer += Length;
    }

    return Attribute;

Cleanup:

    if (NULL != Attribute) {
        CmsFreeAttributeValues(Attribute->Values);
        CmsFreePool(Attribute);
    }

    return NULL;
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

PCMS_SIGNER_INFO
CmsParseSignerInfo (
    _In_ PUINT8 SignerInfoData,
    _In_ SIZE_T SignerInfosLength
)
{
    INT Result;
    PUINT8 Pointer;
    PUINT8 SignerInfoEnd;
    PUINT8 SignedAttributesEnd;
    PUINT8 UnsignedAttributesEnd;
    SIZE_T Length;
    PCMS_SIGNER_INFO SignerInfo;
    PCMS_ATTRIBUTE Attribute;
    PCMS_ATTRIBUTE Node;

    Pointer = SignerInfoData;
    SignerInfoEnd = SignerInfoData + SignerInfosLength;

    SignerInfo = CmsAllocatePoolZero(sizeof(CMS_SIGNER_INFO));

    if (NULL == SignerInfo) {
        goto Cleanup;
    }

    if (mbedtls_asn1_get_int(&Pointer, SignerInfoEnd, &SignerInfo->Version) != 0) {
        goto Cleanup;
    }

    if (SignerInfo->Version != 1) {
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    SignerInfo->IssuerAndSerialNumber.Data = Pointer;
    SignerInfo->IssuerAndSerialNumber.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    SignerInfo->DigestAlgorithm.Data = Pointer;
    SignerInfo->DigestAlgorithm.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
        SignedAttributesEnd = Pointer + Length;

        while (TRUE) {
            Result = mbedtls_asn1_get_tag(&Pointer, SignedAttributesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                goto Cleanup;
            }

            Attribute = CmsParseAttribute(Pointer, Length);

            if (NULL == Attribute) {
                goto Cleanup;
            }

            if (NULL == SignerInfo->SignedAttributes) {
                SignerInfo->SignedAttributes = Attribute;
            }
            else {
                Node = SignerInfo->SignedAttributes;

                while (Node->Next != NULL) {
                    Node = Node->Next;
                }

                Node->Next = Attribute;
            }

            Pointer += Length;
        }
    }

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    SignerInfo->SignatureAlgorithm.Data = Pointer;
    SignerInfo->SignatureAlgorithm.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_OCTET_STRING) != 0) {
        goto Cleanup;
    }

    SignerInfo->Signature.Data = Pointer;
    SignerInfo->Signature.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, SignerInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1) == 0) {
        UnsignedAttributesEnd = Pointer + Length;

        while (TRUE) {
            Result = mbedtls_asn1_get_tag(&Pointer, UnsignedAttributesEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

            if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
                break;
            }

            if (0 != Result) {
                goto Cleanup;
            }

            Attribute = CmsParseAttribute(Pointer, Length);

            if (NULL == Attribute) {
                goto Cleanup;
            }

            if (NULL == SignerInfo->UnsignedAttributes) {
                SignerInfo->UnsignedAttributes = Attribute;
            }
            else {
                Node = SignerInfo->UnsignedAttributes;

                while (Node->Next != NULL) {
                    Node = Node->Next;
                }

                Node->Next = Attribute;
            }

            Pointer += Length;
        }
    }

    return SignerInfo;

Cleanup:

    if (NULL != SignerInfo) {
        CmsFreeAttributes(SignerInfo->SignedAttributes);
        CmsFreeAttributes(SignerInfo->UnsignedAttributes);
        CmsFreePool(SignerInfo);
    }

    return NULL;
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

PCMS_PKCS7_DER
CmsParsePkcs7Der (
    _In_ PUINT8 Pkcs7Data,
    _In_ SIZE_T Pkcs7Length
)
{
    INT Result;
    PUINT8 Buffer;
    PUINT8 Pointer;
    PUINT8 Pkcs7End;
    PUINT8 ContentInfoEnd;
    PUINT8 ContentEnd;
    PUINT8 EncapsulatedContentInfoEnd;
    PUINT8 CertificatesEnd;
    PUINT8 SignerInfosEnd;
    PCMS_PKCS7_DER Pkcs7Der;
    PCMS_SIGNER_INFO SignerInfos;
    PCMS_SIGNER_INFO Node;
    SIZE_T Length;

    Pointer = Pkcs7Data;
    Pkcs7End = Pkcs7Data + Pkcs7Length;

    Pkcs7Der = CmsAllocatePoolZero(sizeof(CMS_PKCS7_DER));

    if (NULL == Pkcs7Der) {
        goto Cleanup;
    }

    mbedtls_x509_crt_init(&Pkcs7Der->SignedData.Certificates);
    mbedtls_x509_crl_init(&Pkcs7Der->SignedData.CertificateRevocationLists);

    if (mbedtls_asn1_get_tag(&Pointer, Pkcs7End, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    ContentInfoEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentInfoEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        goto Cleanup;
    }

    if (Length != sizeof(MBEDTLS_OID_PKCS7_SIGNED_DATA) - 1) {
        goto Cleanup;
    }

    if (memcmp(Pointer, MBEDTLS_OID_PKCS7_SIGNED_DATA, sizeof(MBEDTLS_OID_PKCS7_SIGNED_DATA) - 1) != 0) {
        goto Cleanup;
    }

    Pkcs7Der->ContentTypeOid.Data = Pointer;
    Pkcs7Der->ContentTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) != 0) {
        goto Cleanup;
    }

    ContentEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    if (mbedtls_asn1_get_int(&Pointer, ContentEnd, &Pkcs7Der->SignedData.Version) != 0) {
        goto Cleanup;
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        goto Cleanup;
    }

    Pkcs7Der->SignedData.DigestAlgorithms.Data = Pointer;
    Pkcs7Der->SignedData.DigestAlgorithms.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        goto Cleanup;
    }

    EncapsulatedContentInfoEnd = Pointer + Length;

    if (mbedtls_asn1_get_tag(&Pointer, EncapsulatedContentInfoEnd, &Length, MBEDTLS_ASN1_OID) != 0) {
        goto Cleanup;
    }

    Pkcs7Der->SignedData.EncapsulatedContentInfo.ContentTypeOid.Data = Pointer;
    Pkcs7Der->SignedData.EncapsulatedContentInfo.ContentTypeOid.Length = Length;
    Pointer += Length;

    if (mbedtls_asn1_get_tag(&Pointer, EncapsulatedContentInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
        Pkcs7Der->SignedData.EncapsulatedContentInfo.Content.Data = Pointer;
        Pkcs7Der->SignedData.EncapsulatedContentInfo.Content.Length = Length;
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
                goto Cleanup;
            }

            Pointer += Length;
            Result = mbedtls_x509_crt_parse_der(&Pkcs7Der->SignedData.Certificates, Buffer, Pointer - Buffer);

            if (0 != Result) {
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
                goto Cleanup;
            }

            Pointer += Length;
            Result = mbedtls_x509_crl_parse_der(&Pkcs7Der->SignedData.CertificateRevocationLists, Buffer, Pointer - Buffer);

            if (0 != Result) {
                goto Cleanup;
            }
        }
    }

    if (mbedtls_asn1_get_tag(&Pointer, ContentEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
        goto Cleanup;
    }

    SignerInfosEnd = Pointer + Length;

    while (TRUE) {
        Result = mbedtls_asn1_get_tag(&Pointer, SignerInfosEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

        if (MBEDTLS_ERR_ASN1_OUT_OF_DATA == Result) {
            break;
        }

        if (0 != Result) {
            goto Cleanup;
        }

        SignerInfos = CmsParseSignerInfo(Pointer, Length);

        if (NULL == SignerInfos) {
            goto Cleanup;
        }

        if (NULL == Pkcs7Der->SignedData.SignerInfos) {
            Pkcs7Der->SignedData.SignerInfos = SignerInfos;
        }
        else {
            Node = Pkcs7Der->SignedData.SignerInfos;

            while (Node->Next != NULL) {
                Node = Node->Next;
            }

            Node->Next = SignerInfos;
        }

        Pointer += Length;
    }

    return Pkcs7Der;

Cleanup:

    if (NULL != Pkcs7Der) {
        mbedtls_x509_crt_free(&Pkcs7Der->SignedData.Certificates);
        mbedtls_x509_crl_free(&Pkcs7Der->SignedData.CertificateRevocationLists);

        CmsFreeSignerInfos(Pkcs7Der->SignedData.SignerInfos);
        CmsFreePool(Pkcs7Der);
    }

    return NULL;
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

VOID
CmsPrintCertificateInfo (
    _In_ PCMS_X509_CERTIFICATE Certificate
)
{
    PCHAR Buffer;

    Buffer = CmsAllocatePoolZero(0x10001);

    if (NULL != Buffer) {
        CmsDbgPrint("============Certificate Information============\n");
        
        mbedtls_x509_crt_info(Buffer, 0x10000, "", Certificate);
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
    PCMS_PKCS7_DER Pkcs7Der;
    PCMS_X509_CERTIFICATE Certificate;
    PCMS_ATTRIBUTE UnsignedAttribute;
    PCMS_ATTRIBUTE_VALUE UnsignedAttributeValue;

    Pkcs7Der = CmsParsePkcs7Der(Pkcs7Data, Pkcs7Length);

    if (NULL != Pkcs7Der) {
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
