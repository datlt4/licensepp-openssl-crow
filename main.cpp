#include "crow_all.h"
#include "license-manager.h"

int main(int argc, char **argv)
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]() { return "Licensepp + OpenSSL + Crow"; });

    CROW_ROUTE(app, "/license/<string>")
        .methods("GET"_method, "POST"_method)([](const crow::request &req, std::string path) {
            try
            {
                if (req.method == "GET"_method)
                {
                    std::string additionalPayload;
                    unsigned int period = 86400U;
                    std::string Id = "";
                    std::string licensee = "EMoi_ltd";

                    if (req.url_params.get("serial") == nullptr)
                    {
                        std::cout << TAGLINE << __func__ << std::endl;
                        return crow::response(400);
                    }
                    additionalPayload = std::string(req.url_params.get("serial"));
                    if (req.url_params.get("authorityId") != nullptr)
                        Id = std::string(req.url_params.get("authorityId"));
                    else
                        Id = "c1";

                    if (req.url_params.get("period") != nullptr)
                        period = static_cast<unsigned int>(std::stoi(std::string(req.url_params.get("period"))));

                    if (req.url_params.get("licensee") != nullptr)
                        licensee = std::string(req.url_params.get("licensee"));

                    std::cout << additionalPayload << "  " << period << "  " << licensee << std::endl;

                    P_LIC::licenseInfo lInfo{LICENSEE_SIGNATURE, licensee, "", "", additionalPayload, period};
                    P_LIC::getAuthorityIdSecret(Id, lInfo);
                    P_LIC::P_DATA licData;
                    if (issuing(lInfo, licData))
                    {
                        crow::response res(200, std::string((char *)licData.ptr, licData.size));
                        res.add_header("Content-Disposition", "attachment; filename=" + path);
                        res.add_header("Content-Type", "application/octet-stream");
                        return res;
                    }
                    else
                        return crow::response(404, std::string("{\"message\":\"Error when generating license\"}"));
                }
                else if (req.method == "POST"_method)
                {
                    std::string additionalPayload = "";
                    unsigned int period = 86400U;
                    std::string Id = "";
                    std::string licensee = "EMoi_ltd";
                    std::string enc_pass = ENC_PASS;
                    int enc_iter = ENC_ITER;

                    crow::multipart::message msg(req);
                    if (msg.part_map.find("serial") != msg.part_map.end())
                        additionalPayload = msg.part_map.find("serial")->second.body;
                    else
                        return crow::response(400);
                    if (msg.part_map.find("authorityId") != msg.part_map.end())
                        Id = msg.part_map.find("authorityId")->second.body;
                    else
                        Id = "c1";
                    if (msg.part_map.find("period") != msg.part_map.end())
                        period = std::atoi(msg.part_map.find("period")->second.body.c_str());
                    if (msg.part_map.find("licensee") != msg.part_map.end())
                        licensee = msg.part_map.find("licensee")->second.body;
                    if (msg.part_map.find("enc_pass") != msg.part_map.end())
                        enc_pass = msg.part_map.find("enc_pass")->second.body;
                    if (msg.part_map.find("enc_iter") != msg.part_map.end())
                        enc_iter = std::atoi(msg.part_map.find("enc_iter")->second.body.c_str());

                    P_LIC::licenseInfo lInfo{LICENSEE_SIGNATURE, licensee, "c1-secret-passphrase", "c1",
                                             additionalPayload,  period};
                    P_LIC::getAuthorityIdSecret(Id, lInfo);

                    P_LIC::P_DATA licData;
                    P_LIC::P_DATA encData;
                    issuing(lInfo, licData);
                    // licData.save_all("c5.lic");
                    encrypt(licData, encData, enc_pass.c_str(), enc_iter);
                    crow::response res(200, std::string((char *)encData.ptr, encData.size));
                    res.add_header("Content-Disposition", "attachment; filename=" + path);
                    res.add_header("Content-Type", "application/octet-stream");
                    return res;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "[ERROR] " << e.what() << std::endl;
                return crow::response(500, std::string("{\"message\":\"") + std::string(e.what()) + std::string("\"}"));
            }
        });

    CROW_ROUTE(app, "/validate").methods("POST"_method)([](const crow::request &req) {
        try
        {
            P_LIC::P_DATA encData;
            P_LIC::P_DATA decData;
            licensepp::License license;

            std::string file = "";
            std::string enc_pass = ENC_PASS;
            int enc_iter = ENC_ITER;

            crow::multipart::message msg(req);
            if (msg.part_map.find("file") != msg.part_map.end())
                file = msg.part_map.find("file")->second.body;
            else
                return crow::response(400);
            if (msg.part_map.find("enc_pass") != msg.part_map.end())
                enc_pass = msg.part_map.find("enc_pass")->second.body;
            if (msg.part_map.find("enc_iter") != msg.part_map.end())
                enc_iter = std::atoi(msg.part_map.find("enc_iter")->second.body.c_str());

            encData.m_write((void *)file.c_str(), file.length(), true);
            P_LIC::decrypt(encData, decData, enc_pass.c_str(), enc_iter);
            licensepp::VALIDATE_ERROR val_err = P_LIC::validate(decData, license);
            if (!static_cast<int>(val_err.error_code))
            {
                crow::response res(200, license.raw());
                res.add_header("Content-Type", "application/json");
                return res;
            }
            else
            {
                // return crow::response(422, "License is NOT valid");
                return crow::response(422, std::string("{\"message\":\"") + val_err.message + std::string("\"}"));
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500, std::string("{\"message\":\"") + std::string(e.what()) + std::string("\"}"));
        }
    });

    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request &req) {
        try
        {
            P_LIC::P_DATA rawData;
            P_LIC::P_DATA encData;

            std::string file = "";
            std::string enc_pass = ENC_PASS;
            int enc_iter = ENC_ITER;

            crow::multipart::message msg(req);
            if (msg.part_map.find("file") != msg.part_map.end())
                file = msg.part_map.find("file")->second.body;
            else
                return crow::response(400);
            if (msg.part_map.find("enc_pass") != msg.part_map.end())
                enc_pass = msg.part_map.find("enc_pass")->second.body;
            if (msg.part_map.find("enc_iter") != msg.part_map.end())
                enc_iter = std::atoi(msg.part_map.find("enc_iter")->second.body.c_str());

            rawData.m_write((void *)file.c_str(), file.length(), true);
            if (P_LIC::encrypt(rawData, encData, enc_pass.c_str(), enc_iter))
            {
                crow::response res(200, std::string((char *)encData.ptr, encData.size));
                res.add_header("Content-Disposition", "attachment; filename=enc");
                res.add_header("Content-Type", "application/octet-stream");
                return res;
            }
            else
                return crow::response(500, std::string("{\"message\":\"Error when encrypting!\"}"));
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500, std::string("{\"message\":\"") + std::string(e.what()) + std::string("\"}"));
        }
    });

    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request &req) {
        try
        {
            P_LIC::P_DATA encData;
            P_LIC::P_DATA decData;

            std::string file = "";
            std::string enc_pass = ENC_PASS;
            int enc_iter = ENC_ITER;

            crow::multipart::message msg(req);
            if (msg.part_map.find("file") != msg.part_map.end())
                file = msg.part_map.find("file")->second.body;
            else
                return crow::response(400);
            if (msg.part_map.find("enc_pass") != msg.part_map.end())
                enc_pass = msg.part_map.find("enc_pass")->second.body;
            if (msg.part_map.find("enc_iter") != msg.part_map.end())
                enc_iter = std::atoi(msg.part_map.find("enc_iter")->second.body.c_str());

            encData.m_write((void *)file.c_str(), file.length(), true);
            if (P_LIC::decrypt(encData, decData, enc_pass.c_str(), enc_iter))
            {
                crow::response res(200, std::string((char *)decData.ptr, decData.size));
                res.add_header("Content-Disposition", "attachment; filename=dec");
                res.add_header("Content-Type", "application/octet-stream");
                return res;
            }
            else
                return crow::response(500, std::string("{\"message\":\"Error when decrypting!\"}"));
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500, std::string("{\"message\":\"") + std::string(e.what()) + std::string("\"}"));
        }
    });

    // ignore all log
    crow::logger::setLogLevel(crow::LogLevel::INFO);

    int port = (argc == 2) ? std::atoi(argv[1]) : 6262;
    app.port(port).server_name("CrowLicenseppOpenssl").multithreaded().run();

    return 0;
}