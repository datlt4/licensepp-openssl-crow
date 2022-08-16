# licensepp-openssl

## Sample `encrypt` function

```cpp
FILE *fIN, *fOUT;
fIN = fopen("raw_file.bin", "rb");
fOUT = fopen("encrypted.bin", "wb");
encrypt(fIN, fOUT);
fclose(fIN);
fclose(fOUT);
```

## Sample `decrypt` function

```cpp
FILE *fIN, *fOUT;
fIN = fopen("encrypted.bin", "rb");
fOUT = fopen("decrypted.bin", "wb");
P_LIC::decrypt(fIN, fOUT);
fclose(fIN);
fclose(fOUT);
```

## Sample for issuing license

```cpp
P_LIC::licenseInfo lInfo1{LICENSEE_SIGNATURE, "EMoi_ltd", "c1-secret-passphrase", "c1", "12th Gen Intel i5-12400F (12) @ 5.600GHz", 87600U};
P_LIC::licenseInfo lInfo2{LICENSEE_SIGNATURE, "EMoi_ltd", "c2-secret-passphrase", "c2", "NVIDIA GeForce RTX 3060", 78840U};
P_LIC::licenseInfo lInfo3{LICENSEE_SIGNATURE, "EMoi_ltd", "c3-secret-passphrase", "c3", "B660M Pro RS", 70080U};
P_LIC::licenseInfo lInfo4{LICENSEE_SIGNATURE, "EMoi_ltd", "c4-secret-passphrase", "c4", "Ubuntu 20.04.4 LTS x86_64", 61320U};
P_LIC::licenseInfo lInfo5{LICENSEE_SIGNATURE, "EMoi_ltd", "c5-secret-passphrase", "c5", "5.15.0-43-generic", 52560U};

licensepp::License license;
bool r1 = P_LIC::issuing(lInfo1, license);
if (r1)
    P_LIC::showLicenseInfo(license);

bool r2 = P_LIC::issuing(lInfo2, "c2.lic");
if (r2)
    std::cout << "SUCCESS" << std::endl;
else
    std::cout << "FAILED!" << std::endl;
```

## Sample for validating license

```cpp
licensepp::License license;
if (P_LIC::validate("c5.lic", license))
    std::cout << "License is valid" << std::endl;
else
    std::cout << "License is NOT valid" << std::endl;
```

## Sample for testing `P_DATA`

```cpp
P_LIC::P_DATA d1;
char c1[10] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
d1.m_write(c1, 10);
std::cout << d1 << std::endl;
d1.show();
char c2[10] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
d1.m_write(c2, 10);
std::cout << d1 << std::endl;
d1.show();
char c3[10] = {0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d};
d1.m_write(c3, 10);
std::cout << d1 << std::endl;
d1.show();
char c4[10] = {0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
d1.m_write(c4, 10);
std::cout << d1 << std::endl;
d1.show();
std::cout << "----------------------------------\n";
P_LIC::P_DATA d2(d1);
std::cout << d2 << std::endl;
d2.show();
std::cout << "----------------------------------\n";
d2 = d1;
std::cout << d2 << std::endl;
d2.show();
std::cout << "----------------------------------\n";
uint8_t c5[40];
std::cout << "[ READ ]: " << d1.m_read(c5, 40) << std::endl;
std::cout << d1 << std::endl;
d1.show();
d1.show_all();
P_LIC::P_DATA d3(d1);
d3.show();
d3.show_all();
```

## Sample for issuing and encrypting license.

```cpp
/* Issuing license file */
P_LIC::licenseInfo lInfo5{LICENSEE_SIGNATURE, "EMoi_ltd", "c5-secret-passphrase", "c5", "5.15.0-43-generic", 52560U};
P_LIC::P_DATA licData;
P_LIC::issuing(lInfo5, licData);
licData.save("c5.lic");
licData.show_all();
// licData.load("c5.lic", true);

/* Encrypt data */
P_LIC::P_DATA encData;
P_LIC::encrypt(licData, encData);
encData.save_all("c5.enc");
encData.show_all();
// encData.load("c5.enc", true);

/* Decrypt encoded data */
P_LIC::P_DATA decData;
P_LIC::decrypt(encData, decData);
decData.save("c5.dec");
decData.show();
// decData.load("c5.dec", true);

/* Validate decoded data */
licensepp::License license;
// validate(decData, license);
if (P_LIC::validate(decData, license))
    std::cout << "License is valid" << std::endl;
else
    std::cout << "License is NOT valid" << std::endl;
```

# Licensepp Sever

## Build server

```bash
cmake .. && make -j$(nproc)
./licensepp-openssl 6262
```

## Issuing license

- **_Generate raw licsence file_**

```bash
curl "http://192.168.120.107:6262/license?serial=10932847102398&period=87600&licensee=EMoi" -o lic
```

- **_Generate encrytped licsence file_**

```bash
curl -X POST \
    -F serial=10932847102398 \
    -F period=87600 \
    -F licensee=EMoi \
    -F enc_pass=9jIY876UJHGuY576tGJU76TUjhg \
    -F enc_iter=280622 \
    http://192.168.120.107:6262/license/lic -o c5.enc

# minimum command
curl -X POST \
    -F serial=10932847102398 \
    http://192.168.120.107:6262/license/lic -o c5.enc
```

## Validate license

```bash
curl -X POST \
    -F file=@c5.enc \
    -F enc_pass=9jIY876UJHGuY576tGJU76TUjhg \
    -F enc_iter=280622 \
    http://192.168.120.107:6262/validate | python -m json.tool

# minimum command
curl -X POST \
    -F file=@c5.enc \
    http://192.168.120.107:6262/validate | python -m json.tool
```

## Encrypt file

```bash
curl -X POST \
    -F file=@c5.lic \
    -F enc_pass=9jIY876UJHGuY576tGJU76TUjhg \
    -F enc_iter=280622 \
    http://192.168.120.107:6262/encrypt -o c5.enc

# minimum command
curl -X POST \
    -F file=@c5.lic \
    http://192.168.120.107:6262/encrypt -o c5.enc
```

## Decrypt file

```bash
curl -X POST \
    -F file=@c5.enc \
    -F enc_pass=9jIY876UJHGuY576tGJU76TUjhg \
    -F enc_iter=280622 \
    http://192.168.120.107:6262/decrypt -o c5.dec

# minimum command
curl -X POST \
    -F file=@c5.enc \
    http://192.168.120.107:6262/decrypt -o c5.dec
```

## Dockerhub

[link](https://hub.docker.com/repository/docker/hienanh/licensepp-openssl-crow)