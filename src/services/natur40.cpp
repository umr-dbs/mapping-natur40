
#include "services/httpservice.h"
#include "userdb/userdb.h"
#include "util/configuration.h"
#include <util/curl.h>

#include <jwt/jwt.hpp>

/*
 * This class provides methods for Natur 4.0 users
 *
 * Operations:
 * - request = login: login with credential, returns sessiontoken
 *   - parameters:
 *     - token
 *  - request = clientToken: get the client token for provider
 *  - request = sourcelist: list available sources from raster db
 */
class Natur40Service : public HTTPService {
public:
    using HTTPService::HTTPService;

    virtual ~Natur40Service() = default;

private:
    static constexpr const char* EXTERNAL_ID_PREFIX = "JWT:";
    virtual void run();
};

REGISTER_HTTP_SERVICE(Natur40Service,
"natur40");

void Natur40Service::run() {
    try {
        if (params.get("request") == "login") {
            auto dec_obj = jwt::decode(params.get("token"),
                                       jwt::params::algorithms({Configuration::get<std::string>("jwt.algorithm")}),
                                       jwt::params::secret(Configuration::get<std::string>("jwt.provider_key")),
                                       jwt::params::leeway(
                                               Configuration::get<uint32_t>("jwt.allowed_clock_skew_seconds")),
                                       jwt::params::verify(true));

            // example payload {"aud":"http://localhost:8000/","exp":1550594460,"nbf":1550590860,"sub":"example.user"}
            jwt::jwt_payload &payload = dec_obj.payload();

            // TODO: check "aud" parameter for matching VAT instance

            std::string externalId = EXTERNAL_ID_PREFIX + payload.get_claim_value<std::string>("sub");

            std::shared_ptr <UserDB::Session> session;
            try {
                // create session for user if he already exists
                session = UserDB::createSessionForExternalUser(externalId, 8 * 3600);
            } catch (const UserDB::authentication_error &e) {
                // TODO: get user details
                try {
                    auto user = UserDB::createExternalUser(payload.get_claim_value<std::string>("sub"),
                                                           "JWT User",
                                                           payload.get_claim_value<std::string>("sub"), externalId);

                    session = UserDB::createSessionForExternalUser(externalId, 8 * 3600);
                } catch (const std::exception &) {
                    response.sendFailureJSON(concat("could not create new user "));
                    return;
                }
            }

            // save jwt token
            auto &user = session->getUser();
            try {
                user.loadArtifact(user.getUsername(), "jwt", "token")->updateValue(params.get("token"));
            } catch (UserDB::artifact_error &) {
                user.createArtifact("jwt", "token", params.get("token"));
            }

            response.sendSuccessJSON("session", session->getSessiontoken());
            return;
        }

        if (params.get("request") == "clientToken") {
            std::string clientToken = Configuration::get<std::string>("jwt.redirect_token", "");
            if (clientToken != "") {
                response.sendSuccessJSON("clientToken", clientToken);
            } else {
                jwt::jwt_object obj{jwt::params::algorithm({Configuration::get<std::string>("jwt.algorithm")}),
                                    jwt::params::secret(Configuration::get<std::string>("jwt.client_key")),
                                    jwt::params::payload(
                                            {{"redirect", Configuration::get<std::string>("jwt.redirect_url")}})};
                response.sendSuccessJSON("clientToken", obj.signature());
            }
            return;
        }


        auto session = UserDB::loadSession(params.get("sessiontoken"));
        auto user = session->getUser();

        if (params.get("request") == "sourcelist") {
            Json::Value v(Json::ValueType::objectValue);
            try {
                std::string jwt = user.loadArtifact(user.getUsername(), "jwt",
                                                    "token")->getLatestArtifactVersion()->getValue();

                std::string rasterDBUrl = Configuration::get<std::string>("natur40.rasterdb_url", "");

                cURL curl;
                std::stringstream data;
                curl.setOpt(CURLOPT_PROXY, Configuration::get<std::string>("proxy", "").c_str());

                curl.setOpt(CURLOPT_URL, concat(rasterDBUrl, "/rasterdbs.json?bands&code&JWS=", jwt).c_str());
                curl.setOpt(CURLOPT_WRITEFUNCTION, cURL::defaultWriteFunction);
                curl.setOpt(CURLOPT_WRITEDATA, &data);
                curl.perform();

                Json::Reader reader(Json::Features::strictMode());
                Json::Value rasters;
                if (!reader.parse(data.str(), rasters))
                    throw std::runtime_error("Could not parse rasters from Natur40 rasterdb");

                for (auto &raster : rasters["rasterdbs"]) {
                    bool vatTag = false;
                    for (auto &tag : raster["tags"]) {
                        if (tag.asString() == "vat") {
                            vatTag = true;
                            break;
                        }
                    }

                    if (!vatTag) {
                        continue;
                    }

                    Json::Value source(Json::objectValue);

                    std::string sourceName = raster["name"].asString();

                    Json::Value channels(Json::arrayValue);

                    std::string crs = raster["code"].asString();
                    std::string epsg = crs.substr(5);

                    Json::Value coords(Json::objectValue);
                    coords["crs"] = crs;
                    coords["epsg"] = epsg;

                    source["coords"] = coords;


                    for (auto &band : raster["bands"]) {
                        Json::Value channel(Json::objectValue);

                        channel["name"] = band["title"];
                        channel["datatype"] = band["datatype"];

                        channel["file_name"] = concat(rasterDBUrl, "/rasterdb/",
                                                      sourceName,
                                                      "/raster.tiff?band=",
                                                      band["index"].asInt(),
                                                      "&ext=%%%MINX%%%%20%%%MINY%%%%20%%%MAXX%%%%20%%%MAXY%%%",
                                                      "&width=%%%WIDTH%%%&height=%%%HEIGHT%%%"
                                                      "&JWS=%%%JWT%%%&clipped");

                        user.addPermission(concat("data.gdal_source.", channel["file_name"].asString()));

                        channel["channel"] = 1;

                        Json::Value unit(Json::objectValue);
                        unit["unit"] = "unknown";
                        unit["interpolation"] = "continuous";
                        unit["measurement"] = "unknown";
                        unit["min"] = band["vis_min"];
                        unit["max"] = band["vis_max"];

                        channel["unit"] = unit;

                        channels.append(channel);
                    }

                    source["channels"] = channels;

                    source["operator"] = "gdal_ext_source";

                    Json::Value tags(Json::arrayValue);
                    tags.append("natur40");

                    source["tags"] = tags;

                    v[sourceName] = source;
                }


            } catch (UserDB::artifact_error &) {}

            response.sendSuccessJSON("sourcelist", v);
            return;
        }
    }
    catch (const std::exception &e) {
        response.sendFailureJSON(e.what());
    }

}