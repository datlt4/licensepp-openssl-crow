#include "license-manager.h"

int main(int argc, char **argv)
{
    licenseInfo lInfo1{LICENSEE_SIGNATURE, "EMoi_ltd", "c1-secret-passphrase", "c1", "12th Gen Intel i5-12400F (12) @ 5.600GHz", 87600U};
    licenseInfo lInfo2{LICENSEE_SIGNATURE, "EMoi_ltd", "c2-secret-passphrase", "c2", "NVIDIA GeForce RTX 3060", 78840U};
    licenseInfo lInfo3{LICENSEE_SIGNATURE, "EMoi_ltd", "c3-secret-passphrase", "c3", "B660M Pro RS", 70080U};
    licenseInfo lInfo4{LICENSEE_SIGNATURE, "EMoi_ltd", "c4-secret-passphrase", "c4", "Ubuntu 20.04.4 LTS x86_64", 61320U};
    licenseInfo lInfo5{LICENSEE_SIGNATURE, "EMoi_ltd", "c5-secret-passphrase", "c5", "5.15.0-43-generic", 52560U};

    P_DATA licData;
    P_DATA encData;
    P_DATA decData;

    issuing(lInfo1, licData);
    licData.save("c5.lic");
    licData.show_all();

    encrypt(licData, encData);
    encData.save_all("c5.enc");
    encData.show_all();

    decrypt(encData, decData);
    decData.save("c5.dec");
    decData.show();

    licensepp::License license;
    // validate(decData, license);
    if (validate(decData, license))
        std::cout << "License is valid" << std::endl;
    else
        std::cout << "License is NOT valid" << std::endl;

    return 0;
}