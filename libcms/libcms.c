#include <mbedtls/mbedtls_config.h>
#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include "libcms.h"

PCMS_PKCS7_ATTRIBUTE_VALUE
CmsPkcs7ParseAttributeValue (
    _In_ PUINT8 AttributeValueData,
    _In_ SIZE_T AttributeValueLength
)
{
    PCMS_PKCS7_ATTRIBUTE_VALUE AttributeValue;

    AttributeValue = CmsAllocatePoolZero(sizeof(CMS_PKCS7_ATTRIBUTE_VALUE));

    if (NULL == AttributeValue) {
        return NULL;
    }

    AttributeValue->Blob.Data = AttributeValueData;
    AttributeValue->Blob.Length = AttributeValueLength;

    return AttributeValue;
}

VOID
CmsPkcs7FreeAttributeValues (
    _In_ PCMS_PKCS7_ATTRIBUTE_VALUE AttributeValues
)
{
    PCMS_PKCS7_ATTRIBUTE_VALUE Current;
    PCMS_PKCS7_ATTRIBUTE_VALUE Previous;

    if (NULL == AttributeValues) {
        return;
    }

    Current = AttributeValues;

    while (Current != NULL) {
        Previous = Current;
        Current = Current->Next;

        CmsFreePool(Previous);
    }
}

PCMS_PKCS7_ATTRIBUTE
CmsPkcs7ParseAttribute (
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
    PCMS_PKCS7_ATTRIBUTE Attribute;
    PCMS_PKCS7_ATTRIBUTE_VALUE AttributeValue;
    PCMS_PKCS7_ATTRIBUTE_VALUE Node;

    Pointer = AttributeData;
    AttributeEnd = AttributeData + AttributeLength;

    Attribute = CmsAllocatePoolZero(sizeof(CMS_PKCS7_ATTRIBUTE));

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

        AttributeValue = CmsPkcs7ParseAttributeValue(Buffer, Pointer + Length - Buffer);

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
        CmsPkcs7FreeAttributeValues(Attribute->Values);
        CmsFreePool(Attribute);
    }

    return NULL;
}

VOID
CmsPkcs7FreeAttributes (
    _In_ PCMS_PKCS7_ATTRIBUTE Attributes
)
{
    PCMS_PKCS7_ATTRIBUTE Current;
    PCMS_PKCS7_ATTRIBUTE Previous;

    if (NULL == Attributes) {
        return;
    }

    Current = Attributes;

    while (Current != NULL) {
        Previous = Current;
        Current = Current->Next;

        CmsPkcs7FreeAttributeValues(Previous->Values);
        CmsFreePool(Previous);
    }
}

PCMS_PKCS7_SIGNER_INFO
CmsPkcs7ParseSignerInfo (
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
    PCMS_PKCS7_SIGNER_INFO SignerInfo;
    PCMS_PKCS7_ATTRIBUTE Attribute;
    PCMS_PKCS7_ATTRIBUTE Node;

    Pointer = SignerInfoData;
    SignerInfoEnd = SignerInfoData + SignerInfosLength;

    SignerInfo = CmsAllocatePoolZero(sizeof(CMS_PKCS7_SIGNER_INFO));

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

            Attribute = CmsPkcs7ParseAttribute(Pointer, Length);

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

            Attribute = CmsPkcs7ParseAttribute(Pointer, Length);

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
        CmsPkcs7FreeAttributes(SignerInfo->UnsignedAttributes);
        CmsFreePool(SignerInfo);
    }

    return NULL;
}

VOID
CmsPkcs7FreeSignerInfos (
    _In_ PCMS_PKCS7_SIGNER_INFO SignerInfos
)
{
    PCMS_PKCS7_SIGNER_INFO Current;
    PCMS_PKCS7_SIGNER_INFO Previous;

    if (NULL == SignerInfos) {
        return;
    }

    Current = SignerInfos;

    while (Current != NULL) {
        Previous = Current;
        Current = Current->Next;

        CmsPkcs7FreeAttributes(Previous->UnsignedAttributes);
        CmsFreePool(Previous);
    }
}

BOOLEAN
CmsPkcs7ParseDer (
    _In_ PUINT8 Pkcs7Data,
    _In_ SIZE_T Pkcs7Length,
    _Out_ PCMS_PKCS7_DER Pkcs7Der
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
    PCMS_PKCS7_SIGNER_INFO SignerInfos;
    PCMS_PKCS7_SIGNER_INFO Node;
    SIZE_T Length;

    Pointer = Pkcs7Data;
    Pkcs7End = Pkcs7Data + Pkcs7Length;

    memset(Pkcs7Der, 0, sizeof(CMS_PKCS7_DER));

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
        if (mbedtls_asn1_get_tag(&Pointer, EncapsulatedContentInfoEnd, &Length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            goto Cleanup;
        }

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

        SignerInfos = CmsPkcs7ParseSignerInfo(Pointer, Length);

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

    return TRUE;

Cleanup:

    mbedtls_x509_crt_free(&Pkcs7Der->SignedData.Certificates);
    mbedtls_x509_crl_free(&Pkcs7Der->SignedData.CertificateRevocationLists);

    CmsPkcs7FreeSignerInfos(Pkcs7Der->SignedData.SignerInfos);
    Pkcs7Der->SignedData.SignerInfos = NULL;

    return FALSE;
}

VOID
CmsPkcs7FreeDer (
    _Inout_ PCMS_PKCS7_DER Pkcs7Der
)
{
    mbedtls_x509_crt_free(&Pkcs7Der->SignedData.Certificates);
    mbedtls_x509_crl_free(&Pkcs7Der->SignedData.CertificateRevocationLists);

    CmsPkcs7FreeSignerInfos(Pkcs7Der->SignedData.SignerInfos);
    Pkcs7Der->SignedData.SignerInfos = NULL;
}

VOID
PrintCertificate (
    _In_ PCMS_PKCS7_CERTIFICATE_SET Certificate
)
{
    ANSI_STRING AnsiString;
    mbedtls_asn1_named_data *NameData;
    CHAR OidBuffer[128];
    const CHAR *Description;
    mbedtls_pk_type_t PkType;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "====================================\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "    Certificate Information\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "====================================\n\n");

    // Version
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Version]\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  v%d (0x%x)\n\n", Certificate->version, Certificate->version);

    // Serial Number
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Serial Number]\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  ");
    for (SIZE_T i = 0; i < Certificate->serial.len; i++) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X", Certificate->serial.p[i]);
        if (i < Certificate->serial.len - 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, ":");
        }
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n");

    // Issuer
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Issuer]\n");
    NameData = &Certificate->issuer;
    while (NameData != NULL) {
        if (NameData->oid.len > 0) {
            if (mbedtls_oid_get_attr_short_name(&NameData->oid, &Description) == 0) {
                RtlStringCbPrintfA(OidBuffer, sizeof(OidBuffer), "%s", Description);
            } else {
                RtlStringCbPrintfA(OidBuffer, sizeof(OidBuffer), "Unknown");
            }

            AnsiString.Buffer = (PCHAR)NameData->val.p;
            AnsiString.Length = (USHORT)NameData->val.len;
            AnsiString.MaximumLength = AnsiString.Length;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  %-20s = %Z\n", OidBuffer, &AnsiString);
        }
        NameData = NameData->next;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");

    // Subject
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Subject]\n");
    NameData = &Certificate->subject;
    while (NameData != NULL) {
        if (NameData->oid.len > 0) {
            if (mbedtls_oid_get_attr_short_name(&NameData->oid, &Description) == 0) {
                RtlStringCbPrintfA(OidBuffer, sizeof(OidBuffer), "%s", Description);
            } else {
                RtlStringCbPrintfA(OidBuffer, sizeof(OidBuffer), "Unknown");
            }

            AnsiString.Buffer = (PCHAR)NameData->val.p;
            AnsiString.Length = (USHORT)NameData->val.len;
            AnsiString.MaximumLength = AnsiString.Length;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  %-20s = %Z\n", OidBuffer, &AnsiString);
        }
        NameData = NameData->next;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");

    // Validity Period
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Validity]\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
               "  Not Before          : %04d-%02d-%02d %02d:%02d:%02d UTC\n",
               Certificate->valid_from.year, Certificate->valid_from.mon, Certificate->valid_from.day,
               Certificate->valid_from.hour, Certificate->valid_from.min, Certificate->valid_from.sec);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
               "  Not After           : %04d-%02d-%02d %02d:%02d:%02d UTC\n\n",
               Certificate->valid_to.year, Certificate->valid_to.mon, Certificate->valid_to.day,
               Certificate->valid_to.hour, Certificate->valid_to.min, Certificate->valid_to.sec);

    // Signature Algorithm
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Signature Algorithm]\n");
    if (mbedtls_oid_get_sig_alg_desc(&Certificate->sig_oid, &Description) == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  %s\n\n", Description);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Unknown\n\n");
    }

    // Public Key Info
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Public Key Info]\n");
    PkType = mbedtls_pk_get_type(&Certificate->pk);

    switch (PkType) {
    case MBEDTLS_PK_RSA:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Algorithm           : RSA\n");
        break;
    case MBEDTLS_PK_ECKEY:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Algorithm           : EC\n");
        break;
    case MBEDTLS_PK_ECDSA:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Algorithm           : ECDSA\n");
        break;
    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Algorithm           : Unknown (%d)\n", PkType);
        break;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Key Size            : %d bits\n\n", 
               mbedtls_pk_get_bitlen(&Certificate->pk));

    // Extensions
    if (Certificate->ext_types != 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Extensions]\n");

        if (Certificate->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                       "  Basic Constraints   : CA = %s", 
                       Certificate->ca_istrue ? "TRUE" : "FALSE");
            if (Certificate->ca_istrue && Certificate->max_pathlen > 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                           ", pathlen = %d", Certificate->max_pathlen);
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Key Usage           : ");

            BOOLEAN FirstUsage = TRUE;
            if (Certificate->key_usage & MBEDTLS_X509_KU_DIGITAL_SIGNATURE) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Digital Signature");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_NON_REPUDIATION) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sNon Repudiation", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_KEY_ENCIPHERMENT) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sKey Encipherment", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_DATA_ENCIPHERMENT) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sData Encipherment", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_KEY_AGREEMENT) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sKey Agreement", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sCertificate Sign", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            if (Certificate->key_usage & MBEDTLS_X509_KU_CRL_SIGN) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%sCRL Sign", FirstUsage ? "" : ", ");
                FirstUsage = FALSE;
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Subject Alt Name    : Present\n");
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Netscape Cert Type  : 0x%02X\n", Certificate->ns_cert_type);
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Extended Key Usage  : Present\n");
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Subject Key ID      : Present\n");
        }

        if (Certificate->ext_types & MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Authority Key ID    : Present\n");
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
    }

    // Certificate Thumbprint (SHA-256 hash of entire certificate)
    {
        UCHAR Thumbprint[20];
        INT Result;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Certificate Thumbprint (SHA-1)]\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  ");

        Result = mbedtls_sha1(Certificate->raw.p, Certificate->raw.len, Thumbprint);

        if (Result == 0) {
            for (SIZE_T i = 0; i < sizeof(Thumbprint); i++) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X", Thumbprint[i]);
                if (i < sizeof(Thumbprint) - 1) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ");
                }
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n");
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to compute (error: %d)\n\n", Result);
        }
    }

    if (Certificate->sig_md == MBEDTLS_MD_SHA1) {
        UCHAR TbsHash[20];
        INT Result;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ToBeSignedHash (SHA-1)]\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  ");

        Result = mbedtls_sha1(Certificate->tbs.p, Certificate->tbs.len, TbsHash);

        if (Result == 0) {
            for (SIZE_T i = 0; i < sizeof(TbsHash); i++) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X", TbsHash[i]);
                if (i < sizeof(TbsHash) - 1) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ");
                }
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n");
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to compute (error: %d)\n\n", Result);
        }
    }

    if (Certificate->sig_md == MBEDTLS_MD_SHA256) {
        UCHAR TbsHash[32];
        INT Result;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ToBeSignedHash (SHA-256)]\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  ");

        Result = mbedtls_sha256(Certificate->tbs.p, Certificate->tbs.len, TbsHash, 0);

        if (Result == 0) {
            for (SIZE_T i = 0; i < sizeof(TbsHash); i++) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X", TbsHash[i]);
                if (i < sizeof(TbsHash) - 1) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " ");
                }
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n");
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to compute (error: %d)\n\n", Result);
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "====================================\n\n");
}

VOID
TestRecursiveParseDer (
    _In_ PUINT8 Pkcs7Data,
    _In_ SIZE_T Pkcs7Length,
    _In_ UINT32 Index
)
{
    CMS_PKCS7_DER Pkcs7Der;
    PCMS_PKCS7_CERTIFICATE_SET Certificate;
    PCMS_PKCS7_ATTRIBUTE UnsignedAttribute;
    PCMS_PKCS7_ATTRIBUTE_VALUE UnsignedAttributeValue;

    if (FALSE != CmsPkcs7ParseDer(Pkcs7Data, Pkcs7Length, &Pkcs7Der)) {
        Certificate = &Pkcs7Der.SignedData.Certificates;

        while (NULL != Certificate) {
            PrintCertificate(Certificate);
            Certificate = Certificate->next;
        }

        UnsignedAttribute = Pkcs7Der.SignedData.SignerInfos->UnsignedAttributes;

        while (NULL != UnsignedAttribute) {
            UnsignedAttributeValue = UnsignedAttribute->Values;

            while (NULL != UnsignedAttributeValue) {
                TestRecursiveParseDer(UnsignedAttributeValue->Blob.Data, UnsignedAttributeValue->Blob.Length, Index + 1);
                UnsignedAttributeValue = UnsignedAttributeValue->Next;
            }

            UnsignedAttribute = UnsignedAttribute->Next;
        }

        CmsPkcs7FreeDer(&Pkcs7Der);
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

typedef struct _CMS_WIN_CERTIFICATE {
    UINT32 Length;
    UINT16 Revision;
    UINT16 CertificateType;
    UINT8 Certificate[1];
} CMS_WIN_CERTIFICATE, *PCMS_WIN_CERTIFICATE;

#define WIN_CERT_REVISION_1_0               (0x0100)
#define WIN_CERT_REVISION_2_0               (0x0200)

#define WIN_CERT_TYPE_X509                  (0x0001)   // bCertificate contains an X.509 Certificate
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      (0x0002)   // bCertificate contains a PKCS SignedData structure
#define WIN_CERT_TYPE_RESERVED_1            (0x0003)   // Reserved
#define WIN_CERT_TYPE_TS_STACK_SIGNED       (0x0004)   // Terminal Server Protocol Stack Certificate signing

NTSTATUS
TestCmsPkcs7ParseDer (
    VOID
)
{
    NTSTATUS Status;
    UNICODE_STRING FilePathString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle = NULL;
    FILE_STANDARD_INFORMATION StandardInformation = { 0 };
    PUINT8 Buffer = NULL;
    PCMS_WIN_CERTIFICATE Certificate;
    UINT32 SecurityDataSize;
    UINT32 EncodedSignedSize;
    PUINT8 EncodedSignedData;

    RtlInitUnicodeString(&FilePathString, L"\\??\\C:\\test.sys");

    InitializeObjectAttributes(&ObjectAttributes,
                               &FilePathString,
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
        Status = STATUS_ACCESS_VIOLATION;
        goto Cleanup;
    }

    TestRecursiveParseDer(EncodedSignedData, EncodedSignedSize, 0);

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

    DriverObject->DriverUnload = DriverUnload;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "TestCmsPkcs7ParseDer=%08X\n", TestCmsPkcs7ParseDer());

    Status = STATUS_UNSUCCESSFUL;

    return Status;
}
