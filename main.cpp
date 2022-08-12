#include "license-manager.h"
#include "crow_all.h"
// #include "multipart_params.h"

int main(int argc, char **argv)
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]()
     { return "Licensepp + OpenSSL + Crow"; });

    CROW_ROUTE(app, "/license").methods("GET"_method, "POST"_method)([](const crow::request &req)
                                                                     {
        try
        {
            if (req.method == "GET"_method)
            {
                std::string additionalPayload;
                unsigned int period;
                std::string licensee;

                if (req.url_params.get("serial") == nullptr)
                    {std::cout<<TAGLINE<<__func__<<std::endl;
                        return crow::response(400);}
                additionalPayload = std::string(req.url_params.get("serial"));

                if (req.url_params.get("period") == nullptr)
                    period = 86400U;
                else
                    period = static_cast<unsigned int>(std::stoi(std::string(req.url_params.get("period"))));

                if (req.url_params.get("licensee") == nullptr)
                    licensee = "Vizgard_ltd";
                else
                    licensee = std::string(req.url_params.get("licensee"));

                P_LIC::licenseInfo lInfo1{LICENSEE_SIGNATURE, licensee, "c1-secret-passphrase", "c1", additionalPayload, period};
                P_LIC::P_DATA licData;
                P_LIC::P_DATA encData;
                issuing(lInfo1, licData);
                encrypt(licData, encData);
                encData.save_all("enc");
                crow::response res(200, std::string((char*)encData.ptr, encData.size));
                res.add_header("Content-Disposition", "attachment; filename=file.lic");
                res.add_header("Content-Type", "application/octet-stream");
                return res;
            }
            else if (req.method == "POST"_method)
            {
                crow::multipart::message msg(req);
                crow::multipart::part part = msg.get_part_by_name("file");
                // part.body;
                P_LIC::P_DATA encData;
                P_LIC::P_DATA decData;
                licensepp::License license;
                encData.m_write((void*)part.body.c_str(), part.body.length(), true);
                P_LIC::decrypt(encData, decData);
                if (P_LIC::validate(decData, license))
                {
                    crow::response res(200, license.raw());
                    res.add_header("Content-Type", "application/json");
                    return res;
                }
                else
                    return crow::response(422, "License is NOT valid");
            }
            else
                return crow::response(404);
            
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500);
        } });

    CROW_ROUTE(app, "/encrypt").methods("POST"_method)([](const crow::request &req)
                                                       {
        try
        {
            crow::multipart::message msg(req);
            crow::multipart::part part = msg.get_part_by_name("file");
            // part.body;
            P_LIC::P_DATA rawData;
            P_LIC::P_DATA encData;
            licensepp::License license;
            rawData.m_write((void*)part.body.c_str(), part.body.length(), true);
            if (P_LIC::encrypt(rawData, encData))
            {
                crow::response res(200, std::string((char*)encData.ptr, encData.size));
                res.add_header("Content-Disposition", "attachment; filename=file.enc");
                res.add_header("Content-Type", "application/octet-stream");
                return res;
            }
            else
                return crow::response(500);
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500);
        } });

    CROW_ROUTE(app, "/decrypt").methods("POST"_method)([](const crow::request &req)
                                                       {
        try
        {
            crow::multipart::message msg(req);
            crow::multipart::part part = msg.get_part_by_name("file");
            // part.body;
            P_LIC::P_DATA encData;
            P_LIC::P_DATA decData;
            licensepp::License license;
            encData.m_write((void*)part.body.c_str(), part.body.length(), true);
            P_LIC::decrypt(encData, decData);
            if (P_LIC::decrypt(encData, decData))
            {
                crow::response res(200, std::string((char*)decData.ptr, decData.size));
                res.add_header("Content-Disposition", "attachment; filename=file.dec");
                res.add_header("Content-Type", "application/octet-stream");
                return res;
            }
            else
                return crow::response(500);
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500);
        } });

    // ignore all log
    crow::logger::setLogLevel(crow::LogLevel::INFO);

    app.port(6262)
        .server_name("CrowLicenseppOpenssl")
        .multithreaded()
        .run();

    return 0;
}