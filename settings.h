#ifndef __SETTINGS__H
#define __SETTINGS__H

/*----------------------------------------------------------------------
 * IAS API version
 *----------------------------------------------------------------------
 * Default API version to use when querying IAS. 
 *
 * This can be overriden by the -r option to sp.
 */
#define IAS_API_DEF_VERSION    3 

/*----------------------------------------------------------------------
 * CA Certificate Bundles
 *----------------------------------------------------------------------
 * The root CA bundle used to validate the IAS server certificate. The
 * default should be correct for Linux.
 *
 * Windows does not use a bundle file natively, but libcurl for Windows
 * does. If you installed libcurl somewhere other than the default
 * path then you will need to change this.
 *
 * These settings are overridden by the -B option to sp
 */

/* Default CA bundle file on Linux (auto-detected by default, comes from
 * config.h) */
#define DEFAULT_CA_BUNDLE_AUTO "/etc/ssl/certs/ca-certificates.crt"
#define DEFAULT_CA_BUNDLE_LINUX	DEFAULT_CA_BUNDLE_AUTO

/*
 * Intel Attestation Service  Secondary Subscription Key
 * Acquire it using https://api.portal.trustedservices.intel.com/EPID-attestation
 */

#define IAS_PRIMARY_SUBSCRIPTION_KEY "your-primary-sub-key"

/*
 * Intel Attestation Service  Secondary Subscription Key
 * This will be used in case the primary subscription key does not work
 * Acquire it using https://api.portal.trustedservices.intel.com/EPID-attestation
 */

#define IAS_SECONDARY_SUBSCRIPTION_KEY "your-secondary-sub-key"

// Acquire it using https://api.portal.trustedservices.intel.com/EPID-attestation

#define SPID "your-spid"

/*
 * The Intel IAS SGX Report Signing CA file. You are sent this certificate
 * when you apply for access to SGX Developer Services at
 * http://software.intel.com/sgx [REQUIRED]
 */

#define IAS_CERT_FILENAME "ias-cert.pem"

/*
 * Identifies authority that sealed an enclave. Acquired from your enclave.
 */

#define MRSIGNER "your-mrsigner"

#endif
