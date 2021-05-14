/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openthread/platform/crypto.h>

#include <psa/crypto.h>

static otError psaToOtError(psa_status_t aError)
{
    switch (aError)
    {
    case PSA_SUCCESS:
        return OT_ERROR_NONE;
    case PSA_ERROR_INVALID_ARGUMENT:
        return OT_ERROR_INVALID_ARGS;
    default:
        return OT_ERROR_FAILED;
    }
}

static psa_key_type_t toPsaKeyType(otCryptoKeyType aType)
{
    switch (aType)
    {
    case OT_CRYPTO_KEY_TYPE_RAW:
        return PSA_KEY_TYPE_RAW_DATA;
    case OT_CRYPTO_KEY_TYPE_AES:
        return PSA_KEY_TYPE_AES;
    case OT_CRYPTO_KEY_TYPE_HMAC:
        return PSA_KEY_TYPE_HMAC;
    default:
        return PSA_KEY_TYPE_NONE;
    }
}

static psa_algorithm_t toPsaAlgorithm(otCryptoKeyAlgorithm aAlgorithm)
{
    switch (aAlgorithm)
    {
    case OT_CRYPTO_KEY_ALG_AES_ECB:
        return PSA_ALG_ECB_NO_PADDING;
    case OT_CRYPTO_KEY_ALG_HMAC_SHA_256:
        return PSA_ALG_SHA_256;
    default:
        return (psa_algorithm_t) 0;
    }
}

static psa_key_usage_t toPsaKeyUsage(int aUsage)
{
    psa_key_usage_t usage = 0;

    if (aUsage & OT_CRYPTO_KEY_USAGE_EXPORT) {
        usage |= PSA_KEY_USAGE_EXPORT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_ENCRYPT) {
        usage |= PSA_KEY_USAGE_ENCRYPT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_DECRYPT) {
        usage |= PSA_KEY_USAGE_DECRYPT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_SIGN_HASH) {
        usage |= PSA_KEY_USAGE_SIGN_HASH;
    }

    return usage;
}

otError otPlatPsaInit(void)
{
    return psaToOtError(psa_crypto_init());
}

otError otPlatCryptoImportKey(otCryptoKeyRef *     aKeyRef,
                              otCryptoKeyType      aKeyType,
                              otCryptoKeyAlgorithm aKeyAlgorithm,
                              int                  aKeyUsage,
                              otCryptoKeyStorage   aKeyPersistence,
                              const uint8_t *      aKey,
                              size_t               aKeyLen)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attributes, toPsaKeyType(aKeyType));
    psa_set_key_algorithm(&attributes, toPsaAlgorithm(aKeyAlgorithm));
	psa_set_key_usage_flags(&attributes, toPsaKeyUsage(aKeyUsage));

    switch (aKeyPersistence) {
    case OT_CRYPTO_KEY_STORAGE_PERSISTENT:
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attributes, *aKeyRef);
        break;
    case OT_CRYPTO_KEY_STORAGE_VOLATILE:
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        break;
    }

    status = psa_import_key(&attributes, aKey, aKeyLen, aKeyRef);
    psa_reset_key_attributes(&attributes);

    return psaToOtError(status);
}

otError otPlatCryptoExportKey(otCryptoKeyRef aKeyRef, uint8_t *aBuffer, size_t aBufferLen, size_t *aKeyLen)
{
    return psaToOtError(psa_export_key(aKeyRef, aBuffer, aBufferLen, aKeyLen));
}

otError otPlatCryptoDestroyKey(otCryptoKeyRef aKeyRef)
{
    return psaToOtError(psa_destroy_key(aKeyRef));
}

bool otPlatCryptoHasKey(otCryptoKeyRef aKeyRef)
{
    psa_key_attributes_t attributes;
    psa_status_t error = psa_get_key_attributes(aKeyRef, &attributes);

    psa_reset_key_attributes(&attributes);

    return error == PSA_SUCCESS;
}

otError otPlatCryptoHmacSha256Init(void *aContext, size_t aContextSize)
{
    psa_mac_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_mac_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    *operation = psa_mac_operation_init();
    return OT_ERROR_NONE;
}

otError otPlatCryptoHmacSha256Deinit(void *aContext, size_t aContextSize)
{
    psa_mac_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_mac_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_mac_abort(operation));
}

otError otPlatCryptoHmacSha256Start(void *aContext, size_t aContextSize, const otCryptoKey *aKey)
{
    psa_mac_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_mac_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_mac_sign_setup(operation, aKey->mKeyRef, PSA_ALG_HMAC(PSA_ALG_SHA_256)));
}

otError otPlatCryptoHmacSha256Update(void *aContext, size_t aContextSize, const void *aBuf, uint16_t aBufLength)
{
    psa_mac_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_mac_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_mac_update(operation, (const uint8_t*) aBuf, aBufLength));
}

otError otPlatCryptoHmacSha256Finish(void *aContext, size_t aContextSize, uint8_t *aBuf, size_t aBufLength)
{
    psa_mac_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_mac_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    size_t macLength;
    return psaToOtError(psa_mac_sign_finish(operation, aBuf, aBufLength, &macLength));
}

otError otPlatCryptoAesInit(void *aContext, size_t aContextSize)
{
    uint32_t * keyRef = aContext;

    if (aContext == NULL || aContextSize < sizeof(uint32_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    *keyRef = 0;
    return OT_ERROR_NONE;
}

otError otPlatCryptoAesSetKey(void *aContext, size_t aContextSize, const otCryptoKey *aKey)
{
    uint32_t * keyRef = aContext;

    if (aContext == NULL || aContextSize < sizeof(uint32_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    *keyRef = aKey->mKeyRef;
    return OT_ERROR_NONE;
}

otError otPlatCryptoAesEncrypt(void *aContext, size_t aContextSize, const uint8_t *aInput, uint8_t *aOutput)
{
    uint32_t * keyRef = aContext;

    if (aContext == NULL || aContextSize < sizeof(uint32_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    size_t outputLength;
    return psaToOtError(psa_cipher_encrypt(*keyRef, PSA_ALG_ECB_NO_PADDING, aInput, 16, aOutput, 16, &outputLength));
}

otError otPlatCryptoAesFree(void *aContext, size_t aContextSize)
{
    return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Init(void *aContext, size_t aContextSize)
{
    psa_hash_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_hash_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    *operation = psa_hash_operation_init();
    return OT_ERROR_NONE;
}

otError otPlatCryptoSha256Deinit(void *aContext, size_t aContextSize)
{
    psa_hash_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_hash_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_hash_abort(operation));
}

otError otPlatCryptoSha256Start(void *aContext, size_t aContextSize)
{
    psa_hash_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_hash_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_hash_setup(operation, PSA_ALG_SHA_256));
}

otError otPlatCryptoSha256Update(void *aContext, size_t aContextSize, const void *aBuf, uint16_t aBufLength)
{
    psa_hash_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_hash_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    return psaToOtError(psa_hash_update(operation, (const uint8_t*) aBuf, aBufLength));
}

otError otPlatCryptoSha256Finish(void *aContext, size_t aContextSize, uint8_t *aHash, uint16_t aHashSize)
{
    psa_hash_operation_t * operation = aContext;

    if (aContext == NULL || aContextSize < sizeof(psa_hash_operation_t)) {
        return OT_ERROR_INVALID_ARGS;
    }

    size_t hashSize;
    return psaToOtError(psa_hash_finish(operation, aHash, aHashSize, &hashSize));
}
