package dev.hcy917.keyboxchecker.keybox

import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Identity of the certificate that terminates a keybox chain.
 *
 * The issuer is recognised by its **public key**, never by a name. Google's
 * attestation roots carry no common name at all, and any locally generated
 * self-signed root passes every signature check inside a keybox, so matching on
 * subject strings is unreliable *and* unsafe.
 *
 * The pinned keys come from VisionR1/KeyAttestation
 * (`attestation/RootPublicKey.java`); the same keys ship in
 * KimmyXYC/KeyboxChecker as `res/pem/google.pem`, `aosp_ec.pem`, `aosp_rsa.pem`
 * and `knox.pem`, and both projects agree byte for byte on the Google, AOSP and
 * Knox SAK v2 keys. [RootStatus.GOOGLE_RKP] is the RKP signal: the P-384
 * `CN=Key Attestation CA1` root is used exclusively by remotely provisioned
 * keys.
 */
enum class RootStatus {
    /** There was no certificate to inspect. */
    NULL,

    /** The terminal certificate could not be read. */
    FAILED,

    /** Not one of the pinned issuers — treat the chain as unproven. */
    UNKNOWN,

    /** AOSP software attestation root. */
    AOSP,

    /** Google hardware attestation root. */
    GOOGLE,

    /** Google's P-384 RKP root, `CN=Key Attestation CA1`. */
    GOOGLE_RKP,

    /** Samsung Knox attestation root. */
    KNOX,
}

object RootKeys {

    /**
     * `ProvisioningInfo` extension (certsIssued + manufacturer).
     *
     * Only remotely provisioned certificates carry it, so its presence is a
     * second, certificate-level RKP signal that does not depend on the chain
     * ending in a pinned root.
     */
    const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"

    private const val GOOGLE_ROOT_PUBLIC_KEY =
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU" +
            "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j" +
            "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y" +
            "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X" +
            "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI" +
            "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB" +
            "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q" +
            "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp" +
            "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7" +
            "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82" +
            "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+" +
            "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ=="

    private const val GOOGLE_RKP_ROOT_PUBLIC_KEY =
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV" +
            "9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObf" +
            "gDkU2KNXezT9/RQ+XvNslxPHrHCowhGr"

    private const val AOSP_ROOT_EC_PUBLIC_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="

    private const val AOSP_ROOT_RSA_PUBLIC_KEY =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
            "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
            "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
            "+Vfkl5YLCazOkjWFmwIDAQAB"

    private const val KNOX_SAKV1_ROOT_PUBLIC_KEY =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r" +
            "5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDo" +
            "fBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526" +
            "FFAK3slSUgC8RObbxys="

    private const val KNOX_SAKV2_ROOT_PUBLIC_KEY =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA" +
            "46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12" +
            "4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo" +
            "ZsapxB0gAOs0jSPRX5M="

    private const val KNOX_SAKMV1_ROOT_PUBLIC_KEY =
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX" +
            "2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkL" +
            "oiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKs" +
            "n2fbQPtpGlNxgEfd6Y8="

    private val PINNED: Map<String, RootStatus> = buildMap {
        put(GOOGLE_ROOT_PUBLIC_KEY, RootStatus.GOOGLE)
        put(GOOGLE_RKP_ROOT_PUBLIC_KEY, RootStatus.GOOGLE_RKP)
        put(AOSP_ROOT_EC_PUBLIC_KEY, RootStatus.AOSP)
        put(AOSP_ROOT_RSA_PUBLIC_KEY, RootStatus.AOSP)
        put(KNOX_SAKV1_ROOT_PUBLIC_KEY, RootStatus.KNOX)
        put(KNOX_SAKV2_ROOT_PUBLIC_KEY, RootStatus.KNOX)
        put(KNOX_SAKMV1_ROOT_PUBLIC_KEY, RootStatus.KNOX)
    }

    /** Base64 of the SPKI without line breaks — the form both projects pin. */
    fun encoded(publicKey: PublicKey?): String? {
        val bytes = runCatching { publicKey?.encoded }.getOrNull() ?: return null
        if (bytes.isEmpty()) return null
        return Base64.getEncoder().encodeToString(bytes)
    }

    fun identify(publicKey: PublicKey?): RootStatus {
        val encoded = encoded(publicKey) ?: return RootStatus.NULL
        return PINNED[encoded] ?: RootStatus.UNKNOWN
    }

    fun identify(certificate: X509Certificate?): RootStatus {
        if (certificate == null) return RootStatus.NULL
        val key = runCatching { certificate.publicKey }.getOrNull()
        if (key == null) return RootStatus.FAILED
        return identify(key)
    }

    /** True when the certificate carries the RKP `ProvisioningInfo` extension. */
    fun hasProvisioningInfo(certificate: X509Certificate?): Boolean {
        if (certificate == null) return false
        return runCatching { certificate.getExtensionValue(PROVISIONING_INFO_OID) != null }
            .getOrDefault(false)
    }

    /** RKP per either signal: the pinned RKP root, or the extension. */
    fun isRemoteProvisioned(root: RootStatus, leaf: X509Certificate?): Boolean =
        root == RootStatus.GOOGLE_RKP || hasProvisioningInfo(leaf)

    /**
     * The pinned table as `status to encoded key` pairs.
     *
     * The constants are generated by script from the two reference projects, so
     * the tests re-decode every one of them and check that [identify] maps it
     * back to the status it was pinned for.
     */
    internal fun pinnedKeys(): List<Pair<RootStatus, String>> =
        PINNED.entries.map { it.value to it.key }
}
