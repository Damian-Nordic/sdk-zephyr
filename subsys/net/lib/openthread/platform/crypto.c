/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define OPENTHREAD_CONFIG_PSA_CRYPTO_ENABLE 1
#include <openthread/platform/psa.h>

#include <psa/crypto.h>

static otError psaToOtError(psa_status_t err)
{
    switch (err)
    {
    case PSA_SUCCESS:
        return OT_ERROR_NONE;
    case PSA_ERROR_INVALID_ARGUMENT:
        return OT_ERROR_INVALID_ARGS;
    default:
        return OT_ERROR_FAILED;
    }
}

otError otPlatPsaInit(void)
{
    return psaToOtError(psa_crypto_init());
}

otError otPlatPsaEcbEncrypt(psa_key_id_t aKeyId, const uint8_t *aInput, uint8_t *aOutput)
{
    size_t outputLength;
    return psaToOtError(psa_cipher_encrypt(aKeyId, PSA_ALG_ECB_NO_PADDING, aInput, 16, aOutput, 16, &outputLength));
}

otError otPlatPsaGenerateKey(psa_key_id_t *        aKeyId,
                             psa_key_type_t        aKeyType,
                             psa_algorithm_t       aKeyAlgorithm,
                             psa_key_usage_t       aKeyUsage,
                             psa_key_persistence_t aKeyPersistence,
                             size_t                aKeyLen)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attributes, aKeyType);
    psa_set_key_algorithm(&attributes, aKeyAlgorithm);
	psa_set_key_usage_flags(&attributes, aKeyUsage);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(aKeyPersistence, PSA_KEY_LOCATION_LOCAL_STORAGE));
    psa_set_key_bits(&attributes, aKeyLen * 8);

    return psaToOtError(psa_generate_key(&attributes, aKeyId));
}

otError otPlatPsaImportKey(psa_key_id_t *        aKeyId,
                           psa_key_type_t        aKeyType,
                           psa_algorithm_t       aKeyAlgorithm,
                           psa_key_usage_t       aKeyUsage,
                           psa_key_persistence_t aKeyPersistence,
                           const uint8_t *       aKey,
                           size_t                aKeyLen)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attributes, aKeyType);
    psa_set_key_algorithm(&attributes, aKeyAlgorithm);
	psa_set_key_usage_flags(&attributes, aKeyUsage);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(aKeyPersistence, PSA_KEY_LOCATION_LOCAL_STORAGE));

    return psaToOtError(psa_import_key(&attributes, aKey, aKeyLen, aKeyId));
}

otError otPlatPsaExportKey(psa_key_id_t aKeyId, uint8_t *aBuffer, uint8_t aBufferLen, size_t *aKeyLen)
{
    return psaToOtError(psa_export_key(aKeyId, aBuffer, aBufferLen, aKeyLen));
}

otError otPlatPsaDestroyKey(psa_key_id_t aKeyId)
{
    return psaToOtError(psa_destroy_key(aKeyId));
}

otError otPlatPsaExportPublicKey(psa_key_id_t aKeyId, uint8_t *aOutput, size_t aOutputSize, size_t *aOutputLen)
{
    return psaToOtError(psa_export_public_key(aKeyId, aOutput, aOutputSize, aOutputLen));
}

otError otPlatPsaSignHash(psa_key_id_t    aKeyId,
                          psa_algorithm_t aKeyAlgorithm,
                          uint8_t *       aHash,
                          size_t          aHashSize,
                          uint8_t *       aSignature,
                          size_t          aSignatureSize,
                          size_t *        aSignatureLen)
{
    return psaToOtError(psa_sign_hash(aKeyId, aKeyAlgorithm, aHash, aHashSize, aSignature, aSignatureSize, aSignatureLen));
}

otError otPlatPsaVerifyHash(psa_key_id_t    aKeyId,
                            psa_algorithm_t aKeyAlgorithm,
                            uint8_t *       aHash,
                            size_t          aHashSize,
                            uint8_t *       aSignature,
                            size_t          aSignatureSize)
{
    return psaToOtError(psa_verify_hash(aKeyId, aKeyAlgorithm, aHash, aHashSize, aSignature, aSignatureSize));
}

otError otPlatPsaGetKeyAttributes(psa_key_id_t aKeyId, psa_key_attributes_t *aKeyAttributes)
{
    return psaToOtError(psa_get_key_attributes(aKeyId, aKeyAttributes));
}
