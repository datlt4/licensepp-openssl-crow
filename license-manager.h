//
//  license-manager.h
//  License++
//
//  Copyright © 2018-present Amrayn Web Services
//  https://amrayn.com
//
//  See https://github.com/amrayn/licensepp/blob/master/LICENSE
//  Maintainer: Luong Tan Dat from Vietnam
//

#ifndef LICENSE_MANAGER_H
#define LICENSE_MANAGER_H

#include <cstring>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <iomanip>
#include <mutex>
#include <cctype>
#include <filesystem>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <license++/base-license-manager.h>
#include <license++/issuing-authority.h>

#define ENC_ITER 280622
#define ENC_PASS "9jIY876UJHGuY576tGJU76TUjhg"
#define LICENSEE_SIGNATURE "56D9EFEA5D55C2029EF511F79D49BFFE"

#ifndef TAGLINE
#define TAGLINE "\t<L" << __LINE__ << "> "
#endif // TAGLINE
namespace P_LIC
{
    class LicenseKeysRegister
    {
    public:
        static const uint8_t LICENSE_MANAGER_SIGNATURE_KEY[];
        static const std::vector<licensepp::IssuingAuthority> LICENSE_ISSUING_AUTHORITIES;
    };

    /**
     * @brief License++ signature key is what's used to sign the licensee's signature.
     * This is to protect the information with AES-CBC-128.
     * Signature key is defined in 128-bit array in key register (LICENSE_MANAGER_SIGNATURE_KEY)
     * You can use `ripe` to generate new key: `ripe -g --aes --length 128`
     *
     */
    inline const uint8_t LicenseKeysRegister::LICENSE_MANAGER_SIGNATURE_KEY[16] = {0x56, 0xD9, 0xEF, 0xEA, 0x5D, 0x55, 0xC2, 0x02, 0x9E, 0xF5, 0x11, 0xF7, 0x9D, 0x49, 0xBF, 0xFE};

    /**
     * @brief Authority key is what is in key register (LICENSE_ISSUING_AUTHORITIES)
     * You will need to generate a custom key for your software.
     * This key is used to sign the digital license.
     * You can use `ripe` command to generate new authority key: `ripe -g --rsa --length 2048 [--secret <secret>]`
     */
    inline const std::vector<licensepp::IssuingAuthority> LicenseKeysRegister::LICENSE_ISSUING_AUTHORITIES = {
        licensepp::IssuingAuthority("c1", // ID
                                    "Custom 1",
                                    /*ripe -g --rsa --length 2048 --secret "c1-secret-passphrase"*/ "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KUHJvYy1UeXBlOiA0LEVOQ1JZUFRFRA0KREVLLUluZm86IEFFUy0yNTYtQ0JDLEJEQjNCMUQ3Q0ZDNjA4OTU4MzlENUZFMkZGQjM0RUQ3DQoNClUycTF1ZFhJME5jY0hyVmNmZlBDaE9kRFp1RzBINlI3Vlo4R1NVYU9HZ0FOSWIyaGVNVGdQOVZHS1hKTXZQSU0KUEJXdm1Qa3J6V1ZTaXFMdlliRnUyYnBXOUZ6OVBic1J4eXZuc3Z5aHl4UnJVcjhyVnc3VjBEMHdsZFVucW9GbQpRam1BOTBWTzFKSlN0M0RucUxGNGdoKzlQWDBGakIvS2JxNlJBVWtTQVpPRFJNTUdEYndWdXB4a2JoSC9EdTNuCmtXUEVaL2RqU3o5WUR6K2ZmdW5oalRuRGRWYXppVVQxWVpybHFRbW02SUNpNU01bThreG51N1FLVEwxRTdMenYKNXhCR290OVZpcUxpOWZJNitJUEwyaUs1aVhYcTE3ckhkRXVRa0p4S3ptZnRxSEtaKzNDU0FDbmd4d1VONVJiOQpzeWFDWHFXU3VYYWxsL2VYYzZoc29wRVhQNTNYK0RFT0dJcmdsOUxNMzhFWTNaem1uNjlpYm1lcmx4eFh1WVVzCjJWQ2E3R1lyTjI3S2ZVOGR6T0lleGw1VHB0eFp5ZjhXalgxTWwrTjkvMFh6TmdaU3dvV3dFbWlNMUdYLytCL3oKc2pKSFd6c3hGYWdUWlg3MXRRbkQ3dmpZZmRXR0VWT2FrNGRvbzY0L1lsRFJYaENsNE9oalVCY2piZ1ZNYVEvTgpPSWdiejhERVlhaWVhbXhtZ0N6Z3dqWWtsK3RBeGljb2dBM3dlTVB6NWtFNzRKK1FPVUNLNW1YRXo5Kzh5V0hCClFOcUNMLy95bnhxNHUwazUzajNSU1dHellZbms0VmdWMWYxbWl5T0RwS0FzN24xUnh1b0I4OHFMNkt2eTlzU20Kd1JNTzRvWDlOc3dIRmoxNkZiL3V2RVB3UDR6QTUxMjVQQURROHo2YXlONSt3RmpOYkdFTDg4ZktJYXdwamNWOQpEalhlSGFVZmxOdXZvajdCTVRTWnFPcjNqV1VBNVBOcVJ3T0tQYmdVamc0eDlBQk55aTRzcjhSVmtwcU0rQi81CldCaFJidVozT0s0UGJlaWxDbU9TQzZSaDhoamtNWnZ3MEkxQTZUOTlFZnpmUFNwK1FUVkhXMk9WQnkyR1RVNVUKODlnSWh6SE1sb1Fvc0hmVXhiRDU0b1cvY0dKYlFjc04rcXZFRFE5UTRPZGlGclVrajRQTDd1M0dNWVlrODAxUAo1WndqdlRwSFZUTDdQRUVia2dIeDVvYTB6K0VlY0tXY0I5QnVPdDV5VWNUelUxczBIZFhaR3ZJaVlFVDZyN3RhCnVjck4wZGl3dVI5LzF1a2NnRklHRUFEc0k1aDNWcWJzRlVoVjNMOFlrNjRNT1Y0emNGNEtPbHIxQm5wZzdOUXoKVGcySTFDdFVyNFR6NjNFeWZYLzNESUh5WjJwQVlYMFR5U203cnZTZit0VGpoUGFmdzFHSjEreTFSNzcrUmwyYwo1NUFrelJSVWdLRk04aUErZEYrQ0ZqZWprc0RiUXBBbXBibTc0eEh6KzViWEgvd0diSyswc0V0UkNQS1NRdE15CnJkemRrSnlGNVBuelRDQVkyQ0diV1NoR0NiSGovRmJjQ2dXdGhZVllCTEptL1pDRWkzMnR6VExDSGdnVmZubmYKMXFhM3lPbXlRS0JoQW80U0lubVBTaXQrckVxWU5FRDhmNXNsWkFFaWJxanhDOFRJYitmcXJPWEFCeS9TYm02ZgpaNnRIalppWFBkZ1hRYXg5UG1TeHhJV3FGN0hqZW90OGJ3UWRSSnRObHBNcWRsVWhnek1JdVdpNE5valFkaVdYCjRUdXNoUkpZdmlBWUtlTG9vVkpaWHJwejcxVXlNYmhUazRxclQvemtDeDkrckU1ZjEyZS9IMGQrRkRBdktVNnIKZW5rbGg4SHhFQ0R4bllYWWNUVHVnbW1OZ0FWZEtFMDVkNkxtWnF2QlNvTlpvWWxnSGpCRUhTZ00yK0Y2QW9YRQpoNHdDc1hMMDZzSVBEYTkwQUt4eEI1dXluellSWHl1Ly85cUJXeXdBdUlWbDhSMjdDWHhvcWh1K3hTM0NPb1lmClBJSUx2RzlOeTFOK05mWWpSdGtmM0R3TmFJS1dsUS9vTjAxeEQ4b1hqaUVYVUk3T2R4SVhUeEFrT0dJVUdnTWQKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0NCg==:LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUTBBTUlJQkNBS0NBUUVBbEcwT00yQzdYUWo2RnFEamYxWU0KSWVXazNTTFNVVWh4NC9Xd2ZiZEhPYlNvcWs0cjFZaWVsc3BQWUl1WjV5a0IrUUx2U0pnYmQveDQwa1V5QUVMWQpEQlZPY25Ed0l0YThPSjhkcktkVGhuUkNVWjRuNlZGeVViYmNPcXkxV1JESHNwdmpEYVZNem1rZlNiVmdOT1FkClFOeEFvU0RUZFZ0UXhUam1icHFKemVGd00zSnJnTGd6QVNwc25GdkpLSTVPMmZ3NHMyN2tLZ0x4VFlka2JIQW8KN1g4RVUzczJ1VG9xRitSVnh2MnAvTWgwV3ZBVUNVM3Q3OEpzRXNEK0I0MHAwZ0tKQmJTWEFkSUhhME50QWw0RQpieFl4Y2c1NmFzUktzYzNmdUdQdFIwQjZLZ1M0UnZXb1BhbFBjdVM3R3hnZFBiV1ZUN2ZGeTBabWE2Zyt3MytqClNRSUJFUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ0K",
                                    87600U, // 10 years max
                                    true),
        licensepp::IssuingAuthority("c2", // ID
                                    "Custom 2",
                                    /*ripe -g --rsa --length 2048 --secret "c2-secret-passphrase"*/ "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KUHJvYy1UeXBlOiA0LEVOQ1JZUFRFRA0KREVLLUluZm86IEFFUy0yNTYtQ0JDLDBFNUU3RUU3QTdDQkVEODcwQTU3M0U4NDU2N0ZENzkxDQoNCjY5TjJlR2QyYW1vcjNNZXI5c1ZGUERUUW5ld1d5M0JPNi9sZ2g1aUx6MWRId3NrR0VTOXJPR3A1VitVMHdoZ2IKdmFTSVlzdE9rOVd5YmpYNmZrQXhsQ1ZOVy8vOTJkYVpIQTAyZSswVW9VejVONUJHdjJtUm5BdlEvanM1WFFKOApoaUdqM016STVYKzVjSE1YVDFpczlmODhFMkpZMmczcVc2Z0VlWEdkZVVidUZEZG9oSVFNSUM4S3FpcWNmTCtQCnp6dHpCT0QrWFRwQ0JBSE9vd1ZMTm14SGdQYlBidkpFNUFOUnl4Q0V1a2FnVk1Tamp6VzNkNGpLRC9COTR1TTkKbUFsZlJGbHJ0UmgvU0txRkRqRGNicWI3OTE1K3lnVEI5S2RDRTdvaU9nUGM5a29zUzdWdzJIY2VHYXFNQk5LVAovRU1SOVg4RDBBV2xpdDh6emdkWk5wakhHT0JYTi9UZHVzZk1NaVNIVDZmNk9BRDFocXdtaFkrK1BsbVh0Zm9NCnZod1JNSEFIa3BkN0QvWUZEbU02dVozRysxdFducytybEhDUGdEay9rRnMvZ3lSdDdTNVJOQTlSYy9Gc1prS0kKRGVXdnFqcXViVWJPMVZIUEp4Zk41b1dZVnE4cEd2M3dpWWQzeWZDUTBjMjJrNHlHd0VHajNVZUxldnJmcUdqcApxMjRTbitMWUJ1eWQ5ci9QVW5nNlVNM1NKODhBa0xUY1c0dUZTTWw2elE2SlB1dkxjTU5mY2o2ZCs5bFN1S2V0CkNQTEhSRTg2WElVMjY3TU9KNThCbmZ4Y3BnRkxMZzdwaDlrSGxtNDlEaEpRZFNRam9xSnZoTDNNU1FJbHRnQy8KT3Qzb0FWeXJjWXhLR2VaaVEweDU2d1A5SytzQ1BaK2NPMmJUcDRtOEpFWmw1UlBZeXM4WnFLeGlmaDdFL29HVApqeUh2cERjWHV5REJXM0s1c1BTMGpEdzlhWjBOVk4vUmNFdy9MMW9tRTAwWVRUOGtFQW85Qk5SZC8vRUVnOFMvCnhrNFZMVTVuNUp5MmdEU2p2K1ZySzRQaUdzOXlwTC85NHlOWklPTmJtWThGbjgvaytrZ1gyT3lPdFp0N3lHRC8Kc1NYdUxHNG5VZVNKK3p2eU9WdEwrN3Vxa3ozL2paSGkvK0kvQm9nTGhzMy9qQ3l1ekNXQU1nK2M5UFlwU1VONApQdVkzS2J6cng1YmZVbG5QMTdXUC9xMjB4MzM5ZjlhdWsyeGlpemdLVit2Z3BJL1RPRE9vOCtyT3NWRGNaQkN4ClVUOVlYU3VoRWd1OU9zTFFXV1lWakVSQW50bjJJTTFxUFJENGY1dTh2cEpUaGdLOWVBWWkzTjVOKzNubGNXOHoKVU9Pb1VyeVRRVmM0V0tRdTNOdzVUNDI5eHJqeUZiRWdVajB5eHNwd29QdVEyZERJYldLNzJHL3VqYW5CelFwagpaU0FnV0FKNUprcmVmaE5rMk9YQkV1OGlsdDBjWDNBbjdYdk91ajkzTkpYb2dCaE9xYm1VWDJjWlJERE92YlBQCk9Ua09rQmZIRzM4NVVMQUZkUmNUN2JXVzNvNGVMNEgrbFI4aWo5RURYdVZpeUx4ZldSaERTTXJLWXV0Y1FhNUcKNFBjU2FORk5tWHhCSSt0RUd1VnZQLzRjZDlrbnRpTTJxYWJjVTQrL2ZzeEtTTXhEeWJqYW5ubGpISzdaQzkrVwo1emQ3YVQ3VDY3WEdpd3hHNkFHUU5pSC9BQzFWK0tIdE8zQnNFSnpQZXZrWU1QUGZaUWl6VVBOT0l3YkpHT05qCjVPVE1rNDRRMHc3QmxnMDBSZ1JkT1dYd0lzVHpXaXg3T3J0UTBJSU9GcWUyUGc5eE9vQittOUkzY2VZdnYydU4KbzNLb3QvL1VlbkZQeWpOTGZjTW0vdTg5Q0M0eTBRVGhFR09sWkFwemxteVgxRG5jNVJiditGRjd2L294YW9RUgp5OTlJcUkySUdCcVdrYXlOUk9pVkRra0tnSk1WUFQxS001ZHBPWXVBWFpJeHdJZ0dnNW1rZVF2andOVjZPcXJvCkpFbFp2ck12aThVMzJDOEM0bGNRNWtoVHJrWnJka29oNzlFV0ZyT3RZVCtMaWdxL1lMV3ZVVGI3bTZoekpwYXcKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0NCg==:LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUTBBTUlJQkNBS0NBUUVBNzM3cVlFUDdYaXpUTEVxWmxueTQKckFLejFNUVBFQklrcExxaTBCQ1pkZmRudmVubjMzZ3BwdFNFREVGWFBtSUNWaitzcWw2aDhPVnk3aWJjMm10Zwo1WEtvNWhVdVh2dGRyZmNkNytrVHcwY2xVVlJSYlQvR3drM281UHRDeDcwUExvczArOTlGbWUva1U2RGZ6N280CmpvWlVEY3VweitXY2FFVW1IU083NEI1ZG5rbzJ5YW0wbVBXQVdqUk5SZTVldVY1MVlMN25QQU5ydXNMRk9rSGMKbUU5R2FpZnBvYVZDNnZTV2pOazJYMVNYdGZLazkwajNIK1NjaXpzODF5QUtBeFBTaGhUb015MFROdlpNbkw3RApscUdEa0RlUno0SXJxNlo0WXZnRWJ4SXJpVytHenVMZ2xsbmIxUndiSkJPMlhYMkFpTVk4MWtoaU5xWFpoMlhoCk5RSUJFUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ0K",
                                    78840U, // 9-year
                                    true),
        licensepp::IssuingAuthority("c3", // ID
                                    "Custom 3",
                                    /*ripe -g --rsa --length 2048 --secret "c3-secret-passphrase"*/ "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KUHJvYy1UeXBlOiA0LEVOQ1JZUFRFRA0KREVLLUluZm86IEFFUy0yNTYtQ0JDLDczRUE3QzgxMTAyQzFBNTJDQkYxM0Q1NjJFN0RBRkJCDQoNCmtQV0YwQjlCR3hZRXB3eFFiMmxlMVdBU1Uwdm1rRGMrMlVJTFlyTFNrT2l3WjlObHNLQ2ZSZFgwTTBpWE4wM0QKWUZkUWNDVW9nN0ZZS05DWU9YMFhkcmhhYXRCYWtuWTZ1NERmZXpuSTluTC81Y05pMnZCemh1c3NQTUpFb1d5RApLeHJJVmJmNWpOdnpSaitadTB3M0ZaRGxIUUhsNFJJbXNJWTk4YS9SdXB1eWZneC9VVkk3aDhKYnRSSlNoWE5UCmliTjg2K1ZvVUN4WlZFSGgzSVVGQ3ltVG8yLzBCbEtLVkUyM3FDTXByR1B5MXZOK1FUbTRIUTdWYnhvNm55akIKWnNTYVk4eFdDSjJYcGxkSGdrRW5FRHNpQU4ySXNuSlY5amdSbXQyM3I5RklVK2xPNjJJOWMxYXNoMWgwbDZmVgpKeHFnaGh4UytoK3JWU2RjbGpxaUE3eGdCRG1lMFc1cUtaTzJRQnF3ZzN4azhCendjTDIwY3cxRkUzUzZuZjRGCkc4bWd2RXdhTlV3alVQQzV5VWx5WElkNlIzVjEvMnVhakZmSXd4ZldGNVpSRHBBRk1TWXY2RytmNS9BNGdDMXgKS2F0NVlvOTlrQkVoc05WNEZDUklrYmFzTEw3Y2dEQVBVNFpSQm9MNndOaGlqdSs0bk5aaGxkQUhlbVFKZVFKQwovQ2ZkeHZXK1g3VjBsczV0MzN3UnNjSys0dk42VmJDQXFhMTVXcEp0K3JWeWNjMEx4aGVyZGtLR2ZDdENFcUhYCkNabUFkTWpFZ2JiUTZtcVdpQmljcXE1bHpvUGJGeEZqSzlBUUpGNmYyczlXS29UdmFaTk12aUg1ZGxYOWlUbVUKNDNLQ3RubGpTN1B1U0hzQ2NxeHo1eTR0NThsRnB4M3J2WEJGOVBQc1lsNUZVMXErNU1GUTVBWlVwcU5DREdJSwpTWVNzNmFybFNDcnUyNGZmZDg2dm8vVEc2RjRuSWhGTUdyNThQUkhuYk5DdVgvMjJ2S0F3bHF5eUdPVVB4RjRCCkJBQnFZaG5SSVMyRCt0clNJQTJXUHlkYVRzRlJOSUtFMzF0bjJVams1NmNPaEViTmVyWjZyQUxjdkpnLy9HV1YKVHNqaFgrMUZoaE5xbUFMZDg3dHhoTnozUUdMRVRPMWhqcTdqdSszZlh4eUI3T1dnemUvMGt6UnBWNXFhTXRKRwp1VlA3c0hYUmdDTkxmc0NqdGcrMTNwV3dUeit5VFFwbmJPSkROTldnTDB4QmIrOGVTbGpTbWRNS2gweUxlSFp6Cnh0cVJLWkRVTUtJK1JVZ1dvL2ptRkxQMmI4U3phazFtZElzNG5kYmFzVmNrbTJwazlGMkJ0WlR6WkNTR0U1Z3AKZGVCSEVjZWxJTzBRZFdQNEhkR0ZrOEhtK1lGY1prOW95c3BuOXAvZ2xqa1lNZjlkWFFCcDRFYU4xQWp0Y284bgpyMjlna3hkSE50OG9hcEdBMVJEdFBBS3F4V2oxM2ZrRmVCWHlnd0h4K2FkcVltL25aSmxtTXBieFNHRUNBajNvCk5ZUVg1S25JaDhxV3lwejNWRUpxRGwrR0pteVFueFAyWDF3WlkydElzOUJYREsvMmFTK0JKamViSncxVHgwVHcKREN1Zk9FVFhVMnc1ekJ3SXVSUUhsUmptNjNqbGlNemJEWXNwZldTelhrdkpoSEVBdjF4U1JXMzFSaCtnK0UzRQo5ZWdWSGV5ZFJBTTBuNE9DK25EMVlDV21wTGJCcENIbG5LODFoY0ZGMEJWRGVScVZoZmtZcE9JS1E2aVVSWnVaCit3R3R1SkVKRkFtdCsreXhxQXlpWXVxVWlud2ptRnI1RU54TE0rL0U5RGtacVZxZ21MQlBKSDZjNlNKd0g1TFYKWDJGRXZNWU1HTFpPRGtDcTZIQnEyVk1mTU5tZlltdExpWDcvNng5NFEvdzljZlEvWXNKaUVDM25qTXgyakExNQphOFFYMnJuYkRZMm9qZkFLY29zeTE2MklINzNOQldVZ00vNkNRaFZGZUg5VGlBcUduVUd3Rk1pUDFqWjRydnQxCkJDQlF6U0ppcFR6UHkrUlJ6aHo0OUpERERySlVJNTkyS2k1RXVEcThiTndOMVl5YURQZmd3Wm9zaWwyVE8yRk0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0NCg==:LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUTBBTUlJQkNBS0NBUUVBcWsrWWhUdjA1NHhCbEZ0WEhZK2sKZGc1VTRxT1gwek80R3I4YVRjbk82YSt4TGdYc1dkZVJGcnovclMvSWNQUlZDSWVsL1VFeUNoZzlCVTU0MmZQWQpsZnFScklHS1NwdnBncjhXUmo0SEVWOURNMzhoOFc0RVh2RHp3MlE4NEdqSTFVLzFVYS9QTmxma2RjcDVXbk9XCnc4RE9CSVpPUzdZRVh0NmJyWFRxclNSb05odkprbUwrYzZ3RXZBZTlIVW43ZUVBQTJkSDE0a3l2dVgrUjFFYXcKb2V3cVB1Z3hmTXJwZEthWGErMUxFZ1ViVlBiUm4wUVlQWlBNVGlobklvdi8wZy9VZ0NPdmp1YzRobEZsKzJScAp3MG5sallWd3ZkN0VhMUF5dk5XM2xLcERqcEROM0RpM2dDZzM1TFV4YTV5Z0RtKzlmY0JDNUtiTWR2cmswNmxkCmFRSUJFUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ0K",
                                    70080U, // 8-year
                                    true),
        licensepp::IssuingAuthority("c4", // ID
                                    "Custom 4",
                                    /*ripe -g --rsa --length 2048 --secret "c4-secret-passphrase"*/ "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KUHJvYy1UeXBlOiA0LEVOQ1JZUFRFRA0KREVLLUluZm86IEFFUy0yNTYtQ0JDLDdCRkUzQkVBNkE3RjMyNUQyNzg4M0U1N0Y1MDZGNkY5DQoNCkNUa0FXTnd5cDNEUTM3Q0RWcUFiU2wzTCtiMjZNNlQwVk4xWkV5eFpjSnhndlllTEtsbk9oRVorbGY2Vkh2Tk8KY3NHS0pMWnFjKysrcm9YeGhTNmcvUlRyZHU3dGpBMFpiMWZtTEtKTHE5MnBFSEdQdDJYYWltRW1ZMTBZMjFFWgpNdmJhUmhsWE01WGZJemZzREVaWVlvK2hVc3haNWRuZ3c3c2NBQXlOajNtMHhoU1ZUUHVITUFrcGlxMGc4ak1NCko3Vk8vT2dhb2k5Z2Jyb3MwS0NrY1o1WGRHd2xodWJ6WHNJcnBnYy9wbmduMGJoalByc05DM3pHYUx6L1M4MUgKSXJxcjNyaVNRN1FTVlRyRnhGTThzVEJRaGNPQVREN3VBMlpuTkM4cVVpQmFlcFlLTmF6Y29BYWZCcmxPS2tHSgpqZVZnektKaU1rSm4rcGM1SVZZamtFWWc5RlEreUU2YnBnUlgyd2ZMaE1VLzloblgxZ1ptUFFWVTJMN2xKbUtMCnZtY0ZQNHgrdjlTaDlRb1hDWmVWNzZNZTVxMXQwaGlQUW1yYU90Tms1alV4ckFIQktFZEpBRlYwVXZMY1JQY1kKcFcvNjk3eWZHbXhHbHlJd2hOY1VvanIwdENJcCtad3R1ZUFyREhhUE1PTGQxckxud1pGcTRURk1VMUkvWDkvTApTai9McFlVeVdDZW5NK2NoRkhUYUFvREhuV2F4NlpkcGZ3dHBaYjlDM0I1S3duNFF2cG5XbTZLM3grTEVpRjlRCmR5T1U1NURVWEdaVFdNOFZyWVcySTgxS2twSWhaMVZUcERWbUh2QVRSOEpKSmZTeFV3TXBJQVB4OG5NN09qY08KblpwRVNYZVdzM0E0RDJWSXVxbzNydlRQem9qWGwzeld1aGVJSkx6eWFHQVdUb0ZQVy9qd0dVQ3k0M0tCend1cwpHd3o5cjRrQ2FXS0VOcWVwa01oQWtLZkV4ZG83MEtTeUhoVHFXOXk5bFdPazJpQTdkb0NkYytIMGJDeml1WGJ1CjFSeURXRHZqQUY0LzIzbklJZTN1b2lPVW1uSVZFTlV1MjBBSEFpZ2kxSE5ORFZma3NRS1l1Z3VFZnV2c0NyU3YKazZ0cFdjT0xNZkdWaXJ2WjhSWk1LelBMTWszeXBXT3Nmem56ZE83VWNIRXNpYng5ZzRaRjNkTmZKUUFNTHo1SQpFZHJrM3BvZlhDMjExUU5FTVE1RWF5RUF6N0tmVEFxZ1hCVWVBclVGdTlib3dzemo1UXl3TEhIZjBCSzF4VWsxCmkrT1RBZm1rZGhoYy9sRWZYWVpBUWVQNXBsSnhDWU5vakhWMlgzWGFKaVFtZ01NUG9mUm5nL3VNMG9ESGx1VUgKeXFCbkJnYjJYVFVQc05hR0N3UTBoVEE1SmlhelVETVZNTXU4TWE3ZDE4bE8wN2xVeHFJNFJCTlJGa05IUmFXNwoyUWJ2bW9HaWp5TTB6L2hqRzIzc2VJemFlQnBtdk03NTFSQkNmQXZKeUZEME1STnh5OHlMZnptTkZhUkdVMi9HCmdYcXQ2YWNWaEhCTEhiNlRrby9NcDRjOXUzTHQ0VGgrRGowZkoxb29aUnF2OWxlMm9HSHJZblZIYllOeHFKbTYKNEhmM1psRjBGQXlLNWtJQUJLeGJQK091WHl6QjRrck1PYWhQdFRlb2U4QlN4VmR1dU0yOGlIRXd0V2ZKVjRobQpxNm5EbFZwZWQ1bXh4MWdpbHJ3Z2VSQzd0blVjVXdrZzZhZ3dLaEMyNnFuMnlkeVZxOUN0RkxJRDFmaUZDUk1HCm9XUEsxUFVUTWh6TkF1OHVOSHdpQ3BmaFJJditlRW5UMlJMczNHZHZkVmIrMXF5WlZoR3NqRnF3NU94NXB2SloKKzl4WkdZUW9LWVFmNExNemhFeFg4TlVvZWU0TnJpWXhOOU4rNE9NaUsxeUxyQy91U3VHbkI5Z0xnNjV4TDJlbgpEajNkVEg0M2VpSHR5RDBRTHFzRXp5VWlkWVVQZE9tbXRPZkRqVXpoMTVpOFFldndtMVB6YzE5MmZ1TjJ1ZEpKCmNvV1l6THVvcDBqSGhjSW94TG1wbHk3MWFvVUlBMnJQTlMwTzNlYXdmVUZjMVZ5TzErM3hScnZkdUhPVWMrcDYKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0NCg==:LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUTBBTUlJQkNBS0NBUUVBcTRVVnRJcHdpclczaWNSVlAydGcKMGNUdTdnM0tSSC9pQWVTUGdNd3d4VkVsK0J1M2FnUVY2M3kvNklUbDhyMmVJN1hyaUQybDVVbVkyVXBNcGd6VQpkU0pVdlo5SEJjQWRRenhrL0M3YVVRK0s5VUpoSFprUTBDcS80eHQrZGVNL2hUa2Jnc3dMWFoxUFA4M3NCUEkwCkJCdkxSeWVOT1NGQ3VNTWVOMldwdCtEWXVPNDJUZDRlUFZWcThYOFVDTSs5aGtSeDJyRktpYVV4TVpuK2YwNkgKNGJ5alhLZksxQkhaV2dIejNDKzNLZk16U1pSbGRadmNTOGRqQmVLMlJRUHY3eWZ3dDRGRmVKd3A1VTFOdTBHWQoza09Nd1I4eEgvSzFET1pxS3o0OExQZ29uSW5QQlZZKzBoeHRUTU9ua0taMlFOWGFwUzN0am9BcE8rcjU0Tlh4CnZ3SUJFUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ0K",
                                    61320U, // 7-year
                                    true),
        licensepp::IssuingAuthority("c5", // ID
                                    "Custom 5",
                                    /*ripe -g --rsa --length 2048 --secret "c5-secret-passphrase"*/ "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KUHJvYy1UeXBlOiA0LEVOQ1JZUFRFRA0KREVLLUluZm86IEFFUy0yNTYtQ0JDLEFBMDgzQjgzMjdCNDFFMTczNjJDNURDMEFFMjRGNDY1DQoNCmRhUnc2OHlVNENCRVJKckY2azh0NDYrbVNJQkxUdmxhTnpYb0tRY01ZL0Rva003ZGFpYVBNN2pua1pxZWQ1VXoKSFNtU2V0aGtDeU5OdXV0VEdFNzk4ajQ5NFVnLzZjcE1XS09abmlLejI3U0VWbUR6dUZtaFZ2akZma21tVEduYgpEM0FuSnIrazRVQXAxWmQyU0FHM3VValE4d2JuVGVWb212Ymw4dWpLZ1Q5eExCbmg3S24wWE95dlZsNklibDhaCkZQRlpPRlh2YUwvUW1rRmNhMnAraXNBVDF6aWVKVDZlelVMc2ttUmtvM2ZOSUVoOHlKN2Vxc3dNcVpuaFZmMk4KZkZOSU0zT3NldXFOME9GNjRvbDlYTmtDakFGWHI5emw3SHM0Y0w2d2VwM2ErNDN1U2VKOXUrQnBrSVI0UEdKWApCNEtrSXpzTDRuTm1qNmpLeC9ZOXhzc0hoSUlTckp2dHljUm11WFFlckJhcmlTR3BETkgvRytoR1UxbEJqK3A0Ck9naFlXNnNTaFUxTUN0K3FmQlVXSUd3RE50TXJuMGI1V3Z0V2Q2Si8zeGdPeEM1SVJ5b0xSQzRGSjJGYjBLaG4KWW01Zml1UmRWVFNSY2ZmeHpyZG82Wi95S3ZKNHNBUGQ3ZFRnb2wrVDVLL2hBZjlYcUoraUIzZjFvVEorKzgzWQptaXJtTEtzUUVmYmt2bjhYODZXbHNyY3o0VjJkT3hpcFVJKzdTQVlmWWFEOGhKeTJrK1ppa2NDL2VQejhCbklMCk1DTGtJM3d2QjJaMnRBeUZsWE40RDNuelY0bnU2dW5DcWtJWlVnSm9qZFIxb0wrZ2l6N0duTDN4NmFWUlFTQi8KeVBMdnN4NlRXSnh4eTVzcmd0SlNGSm5MSW84YzlBdHRNeFREd3pkdEFaZzFvUjFudmFWRUI2aXhmNlBjM2FoagpGcWlzOVZ2blVwZjdMNHA4UE5taC9Wdkc4VHYrR3dvWE5vclRYUWdxTSs1YUhaM2s5SmM1WjlNRlVmclRFZnAvCkF3Y0hXTGFJVGZ0VzRoVXphSWpFYTlzekx6OTd4UEFEQVpwUkNld2RjeVU0S3gwK2JHbmMyRmx2SjlKRU5pRTEKSm5IU0FtYTZ4WTNDNVUza2dRY0JiL2xLa2t0dVZ3d2N0bEpzMC9ocFRMeDdSQldmc3NwaU4wWlM2Q1o2b2h6WgpyM0g0Y1hGMVBBNHk1MHh2VU9iN29TZkZlZFlNS29QcTN6OVV3d2xmNktaN2JKZnFjZUpwQ2Yxcmd2MElHV25LCitFdVN6ZE8vTk1ZdVBsdmNTa1hTN2lZeE5oTk5xbTE3emtNcCs5WGJGWktNdHpjY3JvVEkwdU1PVERUdnYzamoKbDJKTUlNN0hERUh6WGppNUc3bnpBQXMzVk0rU0VrcFpYbW1ubFE4NnIwdU1LR29PbnprRXJjbnExZlhFSkJXQQoxZ0pJL3BsMjg4Vnp3cUJkWjNLVm45Vm5NQ0xtNy9jWDg5L0xnRDVETWdBcGJSL29xdmpXcFJvQVlsOUJWOGpiCjhmSEtlVzJObXdVWTFpV1ZtcTBiS1ZOMENEL3JnSHc3bmJWWWEvU2pkbGdVUTRpRlZ6NEsrTElSdVVFaDZ6MlIKR2VTZzdnZ0JRSzhVd3YyTStHWmVVa1BFZ0pibUd5QlpWOGlRdFNKSStHTitkR1ZERStqL1dab3U0TmZLYWdPcwp4Uk5hZk8wRmhzTDhPeUZ5Q2hKSSt5ZDJ1ekZPYnIyNUhrc2huUktxdWFBSW9PSjk3cUlwZGgvcG5pS2w1V0crCndqNEFpUWxXZGJnK0hCWGJ4MCtSTUNQS3AyZU9rYmdCQmZ4cDE1N01wbFViaVZHcXF0cUZkTXNBTzVSWFhvQXoKNTVHNWRGdE9PUGE2Q0ZUVHdtTkdZS0RPcitrQ2FMTHZBOTRFWkh4U3JoNUtYZldMOHZFUU9XNSthYVo0WnVmUAp1MWh3MGJHeTRmUlJrREtXRGJSZjVXV0NBcjRNSFdLblpaUEhrL015MVNOT2sxQXlWdmZ2L3pMRk0zUTA2N0w3CnFsNHV3SFJSNkFxdGFEV2lYVEZOTWlIckJsdzgwcDkwVEY4RURndmN3OW1rNTJuQzJMc0NWM3VhWGlGc251dUwKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0NCg==:LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUTBBTUlJQkNBS0NBUUVBeXJhWHR3YjVLRG01ck1PTzhGZDcKQ0Fqd3hiV2xKR1lFK3R5Q1l0MmRySm1MSFpZNDRQdXFPWEdUYklJeHJlNmJicnZtajlab2JiZVFxelVDK3VZdApiL25rcUZVNHFhaTJ2V1ZSaXpJalRKUTk0VlVWYTJueHMrSGJsVU5WaVk5M05TaXJhSFZHaUZSVTViSTBqRkNqCi9KQjByYThQN2RiZ3pBL3JQaHVyS2c0QVU3RVpGRVJBTG5xN2pZTXBWOUFjYUttNWp4Z0VjaS9lWlpQd3NveUgKWlUwSmhsK0s5bzdQZjRJR3E0Y0oxSUZNNEFwMGwwQkJXUjhGaHhmYVcyNVNxdUZHUUNWT29IaTkxVkZRY2NYWQpYK25jb0pKS01md2RsSHJJZXlxbDhNdEFxWTR2VWF2dk4yYzlGWGxLQmwxSjJGazloSHg1bkdqMVhyalU5a3J0CjR3SUJFUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ0K",
                                    52560U, // 6-year
                                    true)};

    class LicenseManager : public licensepp::BaseLicenseManager<LicenseKeysRegister>
    {
    public:
        LicenseManager() : BaseLicenseManager() {}
    };

    /**
     * @brief
     *
     */
    template <class T>
    struct pipeline_data
    {
        T *ptr;
        size_t size;
        size_t read;
        std::mutex m_mutex;

        // Default constructor
        pipeline_data() : ptr{nullptr}, size{0}, read{0} {}

        // Default destructor
        ~pipeline_data()
        {
            this->clear();
        }

        // Copy constructor
        pipeline_data(const pipeline_data &copy) : size{copy.size - copy.read}, read{0}
        {
            this->ptr = (T *)malloc(this->size);
            memcpy((void *)this->ptr, (void *)(copy.ptr + copy.read), this->size);
        }

        void clear()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            size = 0;
            read = 0;
            if (this->ptr != nullptr)
            {
                free(this->ptr);
            }
        }

        size_t m_write(void *src, size_t num, bool clear_data = false)
        {
            if (clear_data)
                this->clear();
            std::lock_guard<std::mutex> lock(m_mutex);
            if (this->ptr == nullptr)
            {
                this->ptr = (T *)malloc(num);
            }
            else
            {
                this->ptr = (T *)realloc(this->ptr, this->size + num);
            }
            memcpy((void *)(this->ptr + this->size), src, num);
            this->size += num;
            return num;
        }

        size_t m_read(void *dst, size_t num, bool from_begin = false)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            size_t _from = from_begin ? 0 : this->read;
            if (_from < this->size)
            {
                size_t _num = ((_from + num) < this->size) ? num : (this->size - _from);
                memcpy(dst, (T *)(this->ptr + this->read), _num);
                this->read = _from + _num;
                return _num;
            }
            else
                return 0;
        }

        void save(std::string &filename)
        {
            this->save(filename.c_str());
        }

        void save(char *filename)
        {
            FILE *fOUT;
            fOUT = fopen(filename, "wb");
            fwrite((void *)(this->ptr + this->read), sizeof(T), (this->size - this->read), fOUT);
            fclose(fOUT);
        }

        void save_all(std::string &filename)
        {
            this->save_all(filename.c_str());
        }

        void save_all(char *filename)
        {
            FILE *fOUT;
            fOUT = fopen(filename, "wb");
            fwrite((void *)this->ptr, sizeof(T), this->size, fOUT);
            fclose(fOUT);
        }

        void load(std::string &filename, bool clear_data = false)
        {
            this->load(filename.c_str(), clear_data);
        }

        void load(char *filename, bool clear_data = false)
        {
            const unsigned BUFSIZE = 4096;
            T *read_buf = (T *)malloc(BUFSIZE * sizeof(T));
            FILE *fIN = fopen(filename, "rb");
            while (1)
            {
                int numRead = fread(read_buf, sizeof(T), BUFSIZE, fIN);
                this->m_write((void *)read_buf, numRead * sizeof(T), clear_data);
                if (numRead < BUFSIZE)
                { // EOF
                    break;
                }
            }
            free(read_buf);
        }

        // Overloaded assignment
        pipeline_data &operator=(const pipeline_data &data)
        {
            this->clear();
            this->size = data.size - read;
            this->read = 0;
            this->ptr = (T *)malloc(this->size);
            memcpy((void *)this->ptr, (void *)(data.ptr + data.read), this->size);
            return *this;
        }

        friend std::ostream &operator<<(std::ostream &os, const pipeline_data &data)
        {
            os << "[ ADDRESS ] " << (void *)data.ptr << "  -  [ SIZE ] " << (data.size - data.read);
            return os;
        }

        void show()
        {
            printf("[ %p ]: ", this->ptr);
            for (int i = this->read; i < this->size; ++i)
            {
                printf("0x%02x ", *(this->ptr + i));
            }
            printf("\n");
        }

        void show_all()
        {
            printf("[ %p ]: ", this->ptr);
            for (int i = 0; i < this->size; ++i)
            {
                printf("0x%02x ", *(this->ptr + i));
            }
            printf("\n");
        }
    };

    /**
     * @brief pipeline_data<uint8_t>
     *
     */
    typedef pipeline_data<uint8_t> P_DATA;

    /**
     * @brief
     * @example licenseInfo lInfo1{LICENSEE_SIGNATURE, "EMoi_ltd", "c1-secret-passphrase", "c1", "12th Gen Intel i5-12400F (12) @ 5.600GHz", 87600U};
     * @example licenseInfo lInfo2{LICENSEE_SIGNATURE, "EMoi_ltd", "c2-secret-passphrase", "c2", "NVIDIA GeForce RTX 3060", 78840U};
     * @example licenseInfo lInfo3{LICENSEE_SIGNATURE, "EMoi_ltd", "c3-secret-passphrase", "c3", "B660M Pro RS", 70080U};
     * @example licenseInfo lInfo4{LICENSEE_SIGNATURE, "EMoi_ltd", "c4-secret-passphrase", "c4", "Ubuntu 20.04.4 LTS x86_64", 61320U};
     * @example licenseInfo lInfo5{LICENSEE_SIGNATURE, "EMoi_ltd", "c5-secret-passphrase", "c5", "5.15.0-43-generic", 52560U};
     */
    struct licenseInfo
    {
        std::string licenseeSignature;
        std::string licensee;
        std::string secret;
        std::string authorityId;
        std::string additionalPayload;
        unsigned int period;
    };

    bool encrypt(FILE *ifp, FILE *ofp);
    bool encrypt(P_DATA &idata, P_DATA &odata);
    bool decrypt(FILE *ifp, FILE *ofp);
    bool decrypt(P_DATA &idata, P_DATA &odata);
    void showLicenseInfo(licensepp::License &license);
    bool issuing(licenseInfo &lInfo, licensepp::License &license);
    bool issuing(licenseInfo &lInfo, std::string licPath = "EMoi.lic");
    bool issuing(licenseInfo &lInfo, P_DATA &odata);
    bool validateFromFile(std::string license_file, licensepp::License &license);
    bool validate(std::string license_string, licensepp::License &license);
    bool validate(P_DATA &idata, licensepp::License &license);
};
#endif // LICENSE_MANAGER_H
