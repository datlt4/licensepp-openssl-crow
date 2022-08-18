#include "license-manager.h"

void P_LIC::getAuthorityIdSecret(std::string &Id, P_LIC::licenseInfo &lInfo)
{
    switch (P_LIC::hash(Id.c_str()))
    {
    case P_LIC::hash("0"):
    case P_LIC::hash("sample-license-authority"):
        lInfo.authorityId = "sample-license-authority";
        lInfo.secret = "";
        break;
    case P_LIC::hash("1"):
    case P_LIC::hash("c1"):
        lInfo.authorityId = "c1";
        lInfo.secret = "c1-secret-passphrase";
        break;
    case P_LIC::hash("2"):
    case P_LIC::hash("c2"):
        lInfo.authorityId = "c2";
        lInfo.secret = "c2-secret-passphrase";
        break;
    case P_LIC::hash("3"):
    case P_LIC::hash("c3"):
        lInfo.authorityId = "c3";
        lInfo.secret = "c3-secret-passphrase";
        break;
    case P_LIC::hash("4"):
    case P_LIC::hash("c4"):
        lInfo.authorityId = "c4";
        lInfo.secret = "c4-secret-passphrase";
        break;
    case P_LIC::hash("5"):
    case P_LIC::hash("c5"):
        lInfo.authorityId = "c5";
        lInfo.secret = "c5-secret-passphrase";
        break;
    default:
        lInfo.authorityId = "sample-license-authority";
        lInfo.secret = "";
        break;
    }
}

/**
 * @brief Encypt data from a file stream, this function is equivalent below command: openssl enc -aes-256-cbc -md sha256 -pbkdf2 -iter <ENC_ITER> -k <ENC_PASS> -in <input-filename> -out <output-filename>
 *
 * @param ifp
 * @param ofp
 * @param pass
 * @param iter
 * @return true
 * @return false
 */
bool P_LIC::encrypt(FILE *ifp, FILE *ofp, const char *enc_pass, int enc_iter)
{
    const unsigned BUFSIZE = 4096;
    unsigned char *read_buf = (unsigned char *)malloc(BUFSIZE * sizeof(unsigned char));
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    unsigned char keyivpair[iklen + ivlen];
    unsigned char salt[8];
    if (!(RAND_bytes(salt, sizeof(salt))))
    {
        std::cout << "Call to" << __func__ << "failed\n";
        return false;
    }

    PKCS5_PBKDF2_HMAC((char *)enc_pass, -1, salt, sizeof(salt), enc_iter, EVP_sha256(), iklen + ivlen, keyivpair);
    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 1);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (unsigned char *)malloc((BUFSIZE + blocksize) * sizeof(unsigned char));

    // Generate the actual key IV pair
    fwrite("Salted__", sizeof(unsigned char), 8, ofp);
    fwrite(salt, sizeof(unsigned char), 8, ofp);
    while (1)
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        numRead;
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out.
    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
    // Free memory
    free(cipher_buf);
    free(read_buf);
    return true;
}

/**
 * @brief
 *
 * @param idata
 * @param odata
 * @return true
 * @return false
 */
bool P_LIC::encrypt(P_DATA &idata, P_DATA &odata, const char *enc_pass, int enc_iter)
{
    std::cout << TAGLINE << __func__ << " PASSWORD " << std::string(enc_pass) << "  " << enc_iter << std::endl;
    const uint32_t BUFSIZE = 4096;
    uint8_t *read_buf = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    uint8_t *cipher_buf;
    uint32_t blocksize;
    int out_len;
    uint8_t key[EVP_MAX_KEY_LENGTH];
    uint8_t iv[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    uint8_t keyivpair[iklen + ivlen];
    uint8_t salt[8];
    if (!(RAND_bytes(salt, sizeof(salt))))
    {
        std::cout << "Call to" << __func__ << "failed\n";
        return false;
    }

    PKCS5_PBKDF2_HMAC((char *)enc_pass, -1, salt, sizeof(salt), enc_iter, EVP_sha256(), iklen + ivlen, keyivpair);
    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 1);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (uint8_t *)malloc((BUFSIZE + blocksize) * sizeof(uint8_t));

    // Generate the actual key IV pair
    odata.m_write((void *)"Salted__", sizeof(uint8_t) * 8);
    odata.m_write((void *)salt, sizeof(uint8_t) * 8);
    while (1)
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        int numRead = idata.m_read((void *)read_buf, sizeof(uint8_t) * BUFSIZE);
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        odata.m_write((void *)cipher_buf, sizeof(uint8_t) * (out_len));
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out.
    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    odata.m_write((void *)cipher_buf, sizeof(uint8_t) * out_len);
    // Free memory
    free(cipher_buf);
    free(read_buf);
    return true;
}

/**
 * @brief Decrypt data from a file stream, this function decrypt data encoded by above function.
 *
 * @param ifp
 * @param ofp
 * @param pass
 * @param iter
 * @return true
 * @return false
 */
bool P_LIC::decrypt(FILE *ifp, FILE *ofp, const char *enc_pass, int enc_iter)
{
    const unsigned BUFSIZE = 4096;
    unsigned char *read_buf = (unsigned char *)malloc(BUFSIZE * sizeof(unsigned char));
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    unsigned char keyivpair[iklen + ivlen];
    unsigned char salt[8];
    int numRead = fread(salt, sizeof(unsigned char), 8, ifp);
    numRead = fread(salt, sizeof(unsigned char), 8, ifp);
    PKCS5_PBKDF2_HMAC((char *)enc_pass, -1, salt, sizeof(salt), enc_iter, EVP_sha256(), iklen + ivlen, keyivpair);

    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 0);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (unsigned char *)malloc((BUFSIZE + blocksize) * sizeof(unsigned char));

    // Generate the actual key IV pair
    while (1)
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }
    // Now cipher the final block and write it out.
    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

    // Free memory
    free(cipher_buf);
    free(read_buf);
    return true;
}

/**
 * @brief
 *
 * @param idata
 * @param odata
 * @return true
 * @return false
 */
bool P_LIC::decrypt(P_DATA &idata, P_DATA &odata, const char *enc_pass, int enc_iter)
{
    std::cout << TAGLINE << __func__ << " PASSWORD " << std::string(enc_pass) << "  " << enc_iter << std::endl;
    const unsigned BUFSIZE = 4096;
    uint8_t *read_buf = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    uint8_t *cipher_buf;
    unsigned blocksize;
    int out_len;
    uint8_t key[EVP_MAX_KEY_LENGTH];
    uint8_t iv[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    uint8_t keyivpair[iklen + ivlen];
    uint8_t salt[8];
    int numRead = idata.m_read(salt, sizeof(uint8_t) * 8);
    numRead = idata.m_read(salt, sizeof(uint8_t) * 8);
    PKCS5_PBKDF2_HMAC((char *)enc_pass, -1, salt, sizeof(salt), enc_iter, EVP_sha256(), iklen + ivlen, keyivpair);

    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 0);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (uint8_t *)malloc((BUFSIZE + blocksize) * sizeof(uint8_t));

    // Generate the actual key IV pair
    while (1)
    {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        numRead = idata.m_read(read_buf, sizeof(uint8_t) * BUFSIZE);
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        odata.m_write((void *)cipher_buf, sizeof(uint8_t) * out_len);
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }
    // Now cipher the final block and write it out.
    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    odata.m_write((void *)cipher_buf, sizeof(uint8_t) * out_len);

    // Free memory
    free(cipher_buf);
    free(read_buf);
    return true;
}

/**
 * @brief Print license information
 *
 * @param license
 */
void P_LIC::showLicenseInfo(licensepp::License &license)
{
    std::cout << "[ ID ]: " << license.issuingAuthorityId() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ licensee ]:" << license.licensee() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ issuingAuthorityId ]:" << license.issuingAuthorityId() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ licenseeSignature ]:" << license.licenseeSignature() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ authoritySignature ]:" << license.authoritySignature() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ expiryDate ]:" << license.expiryDate() << " ~ " << license.formattedExpiry() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ issueDate ]:" << license.issueDate() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ additionalPayload ]:" << license.additionalPayload() << std::endl;
    std::cout << "\t" << std::left << std::setw(25) << "[ rawJson ]:" << license.raw() << std::endl;
}

/**
 * @brief Generate license content
 *
 * @param lInfo
 * @param license
 * @return true
 * @return false
 */
bool P_LIC::issuing(licenseInfo &lInfo, licensepp::License &license)
{
    const licensepp::IssuingAuthority *issuingAuthority = nullptr;
    for (const licensepp::IssuingAuthority &a : LicenseKeysRegister::LICENSE_ISSUING_AUTHORITIES)
        if (a.id() == lInfo.authorityId)
            issuingAuthority = &(a);
    if (issuingAuthority == nullptr)
    {
        std::cerr << "Invalid issuing authority.\n";
        return false;
    }
    LicenseManager licenseManager;
    license = licenseManager.issue(lInfo.licensee, lInfo.period, issuingAuthority, lInfo.secret, lInfo.licenseeSignature, lInfo.additionalPayload);
    return true;
}

/**
 * @brief Generate a license file
 *
 * @param lInfo
 * @param licPath
 * @return true
 * @return false
 */
bool P_LIC::issuing(licenseInfo &lInfo, std::string licPath)
{
    licensepp::License license;
    bool ret = issuing(lInfo, license);
    if (ret)
    {
        std::ofstream outfile;
        outfile.open(licPath);
        outfile << license.toString();
        outfile.close();
        return true;
    }
    else
        return false;
}

/**
 * @brief
 *
 * @param lInfo
 * @param odata
 * @return true
 * @return false
 */
bool P_LIC::issuing(licenseInfo &lInfo, P_DATA &odata)
{
    licensepp::License license;
    bool ret = issuing(lInfo, license);
    // showLicenseInfo(license);
    if (ret)
    {
        std::string licData = license.toString();
        odata.m_write((void *)licData.c_str(), licData.length());
        return true;
    }
    else
        return false;
}

/**
 * @brief validate from license file
 *
 * @param license
 * @param license_file
 * @return true
 * @return false
 */
licensepp::VALIDATE_ERROR P_LIC::validateFromFile(std::string license_file, licensepp::License &license)
{
    LicenseManager licenseManager;
    license.loadFromFile(license_file);
    // showLicenseInfo(license);
    return licenseManager.validate(&license, true, LICENSEE_SIGNATURE);
}

/**
 * @brief
 *
 * @param license
 * @param license_string
 * @return true
 * @return false
 */
licensepp::VALIDATE_ERROR P_LIC::validate(std::string license_string, licensepp::License &license)
{
    LicenseManager licenseManager;
    license.load(license_string);
    // showLicenseInfo(license);
    return licenseManager.validate(&license, true, LICENSEE_SIGNATURE);
}

/**
 * @brief
 *
 * @param idata
 * @param license
 * @return true
 * @return false
 */
licensepp::VALIDATE_ERROR P_LIC::validate(P_DATA &idata, licensepp::License &license)
{
    LicenseManager licenseManager;
    idata.m_write((void *)"\0", 1);
    license.load(std::string((char *)idata.ptr));
    // showLicenseInfo(license);
    std::string message;
    return licenseManager.validate(&license, true, LICENSEE_SIGNATURE);
}
