#include "services/httpservice.h"
#include "userdb/userdb.h"
#include "util/configuration.h"
#include <util/curl.h>

#include <jwt/jwt.hpp>

/**
 * This class provides methods for Nature 4.0 users.
 *
 * Requests:
 * - `login`: login with credential, returns sessiontoken
 *      - parameters
 *          - token
 *  - `clientToken`: returns the client token for provider
 *  - `sourcelist`: list available sources from the catalog
 *      - parameters
 *          - sessiontoken: Requires the user to be logged in
 */
class Nature40Service : public HTTPService {
    public:
        using HTTPService::HTTPService;

        ~Nature40Service() override = default;

    private:
        class CatalogEntry {
            public:
                std::string global_id;
                std::string title;
                std::string description;
                std::string user_url;
                std::string provider_type;
                std::string provider_id;
                std::string provider_url;
                std::string dataset_type;
                std::string dataset_id;
                std::string dataset_url;

                explicit CatalogEntry(const Json::Value &json) :
                        global_id(json.get("global_id", "").asString()),
                        title(json.get("title", "").asString()),
                        description(json.get("description", "").asString()),
                        user_url(json.get("user_url", "").asString()),
                        provider_type(json.get("provider", Json::Value(Json::ValueType::arrayValue)).get("type", "").asString()),
                        provider_id(json.get("provider", Json::Value(Json::ValueType::arrayValue)).get("id", "").asString()),
                        provider_url(json.get("provider", Json::Value(Json::ValueType::arrayValue)).get("url", "").asString()),
                        dataset_type(json.get("dataset", Json::Value(Json::ValueType::arrayValue)).get("type", "").asString()),
                        dataset_id(json.get("dataset", Json::Value(Json::ValueType::arrayValue)).get("id", "").asString()),
                        dataset_url(json.get("dataset", Json::Value(Json::ValueType::arrayValue)).get("url", "").asString()) {}

                auto toJson() const -> Json::Value;
        };

        class CatalogEntryMetadata {
            public:

                CatalogEntryMetadata(std::string type, Json::Value metadata) : type(std::move(type)), metadata(std::move(metadata)) {
                    this->metadata["type"] = this->type; // attach type to metadata
                }

                auto toJson() const -> Json::Value;

            private:
                std::string type;
                Json::Value metadata;
        };

        static constexpr const char *EXTERNAL_ID_PREFIX = "JWT:";

        void run() override;

        auto queryCatalog(const std::string &token) -> std::vector<CatalogEntry>;

        auto createCatalogSession(const std::string &token) const -> std::string;

        auto getCatalogJSON(const std::string &sessionId) const -> Json::Value;

        auto resolveCatalogEntry(UserDB::User &user) const -> Json::Value;

        auto getParamAsJson(const std::string &name) const -> Json::Value;

        auto getRSDBRasterMetadata(const std::string &url, const std::string &json_web_token) const -> Json::Value;

        auto composeRSDBRasterMetadata(UserDB::User &user, const CatalogEntry &entry, const Json::Value &metadata) const -> Json::Value;

        auto getRSDBVectorMetadata(const std::string &url, const std::string &json_web_token) const -> Json::Value;

        auto composeRSDBVectorMetadata(UserDB::User &user, const CatalogEntry &entry, const Json::Value &metadata,
                                       const std::string &json_web_token) const -> Json::Value;
};

REGISTER_HTTP_SERVICE(Nature40Service, "nature40"); // NOLINT(cert-err58-cpp)

void Nature40Service::run() {
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

            std::shared_ptr<UserDB::Session> session;
            try {
                // create session for user if he already exists
                session = UserDB::createSessionForExternalUser(externalId, 8 * 3600);
            } catch (const UserDB::authentication_error &e) {
                // TODO: get user details
                try {
                    auto user = UserDB::createExternalUser(payload.get_claim_value<std::string>("sub"),
                                                           "JWT User",
                                                           payload.get_claim_value<std::string>("sub"),
                                                           externalId);

                    session = UserDB::createSessionForExternalUser(externalId, 8 * 3600);
                } catch (const std::exception &) {
                    response.sendFailureJSON("could not create new user ");
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
            if (!clientToken.empty()) {
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
            Json::Value result(Json::ValueType::arrayValue);
            try {
                std::string jwt = user.loadArtifact(user.getUsername(), "jwt",
                                                    "token")->getLatestArtifactVersion()->getValue();
                std::vector<CatalogEntry> entries = queryCatalog(jwt);

                for (const CatalogEntry &e : entries) {
                    result.append(e.toJson());
                }
            } catch (UserDB::artifact_error &) {}

            response.sendSuccessJSON("sourcelist", result);
            return;
        }

        if (params.get("request") == "resolveCatalogEntry") {
            auto result = resolveCatalogEntry(user);
            response.sendSuccessJSON(result);
        }
    }
    catch (const std::exception &e) {
        response.sendFailureJSON(e.what());
    }

}

auto Nature40Service::CatalogEntry::toJson() const -> Json::Value {
    Json::Value v(Json::ValueType::objectValue);
    v["global_id"] = global_id;
    v["title"] = title;
    v["description"] = description;
    v["user_url"] = user_url;

    Json::Value provider(Json::ValueType::objectValue);
    provider["type"] = provider_type;
    provider["id"] = provider_id;
    provider["url"] = provider_url;
    v["provider"] = provider;

    Json::Value dataset(Json::ValueType::objectValue);
    dataset["type"] = dataset_type;
    dataset["id"] = dataset_id;
    dataset["url"] = dataset_url;
    v["dataset"] = dataset;

    // TODO: add parameters that make the data instantiable for the frontend

    return v;
}

auto Nature40Service::createCatalogSession(const std::string &token) const -> std::string {
    cURL curl;
    std::stringstream data;
    curl.setOpt(CURLOPT_PROXY, Configuration::get<std::string>("proxy", "").c_str());

    curl.setOpt(CURLOPT_URL, concat(Configuration::get<std::string>("nature40.catalog_auth_url"), token).c_str());
    curl.setOpt(CURLOPT_WRITEFUNCTION, cURL::defaultWriteFunction);
    curl.setOpt(CURLOPT_WRITEDATA, &data);
    curl.setOpt(CURLOPT_COOKIEFILE, "");
    curl.perform();

    const std::vector<std::string> vector = curl.getCookies();

    if (vector.empty()) {
        throw NetworkException("Nature 4.0 Catalog Cookie missing");
    }

    std::string cookie = vector[0];
    return cookie.substr(cookie.rfind('\t') + 1);
}

auto Nature40Service::getCatalogJSON(const std::string &sessionId) const -> Json::Value {
    cURL curl;
    std::stringstream data;

    curl.setOpt(CURLOPT_PROXY, Configuration::get<std::string>("proxy", "").c_str());

    curl.setOpt(CURLOPT_URL, Configuration::get<std::string>("nature40.catalog_url").c_str());
    curl.setOpt(CURLOPT_WRITEFUNCTION, cURL::defaultWriteFunction);
    curl.setOpt(CURLOPT_COOKIE, concat("session=", sessionId, ";").c_str());
    curl.setOpt(CURLOPT_WRITEDATA, &data);
    curl.setOpt(CURLOPT_COOKIEFILE, "");
    curl.perform();

    Json::Reader reader(Json::Features::strictMode());
    Json::Value entities;
    if (!reader.parse(data.str(), entities))
        throw std::runtime_error("Could not parse from Nature 4.0 catalog");

    return entities;
}

auto Nature40Service::queryCatalog(const std::string &token) -> std::vector<CatalogEntry> {
    Json::Value json = getCatalogJSON(createCatalogSession(token));

    std::vector<CatalogEntry> entries;

    for (const Json::Value &v : json.get("entities", Json::Value(Json::ValueType::arrayValue))) {
        entries.emplace_back(v);
    }

    return entries;
}

auto Nature40Service::getParamAsJson(const std::string &name) const -> Json::Value {
    std::string json_string = this->params.get(name);

    Json::Reader reader(Json::Features::strictMode());
    Json::Value value;

    if (!reader.parse(json_string, value)) {
        throw ArgumentException("Could not parse JSON value");
    }

    return value;
}

auto Nature40Service::resolveCatalogEntry(UserDB::User &user) const -> Json::Value {
    auto json_web_token = user.loadArtifact(user.getUsername(), "jwt", "token")->getLatestArtifactVersion()->getValue();
    auto entry = CatalogEntry(getParamAsJson("entry"));

    const auto UNKNOWN = []() {
        Json::Value error(Json::objectValue);
        error["result"] = false;
        return error;
    };

    if (entry.provider_type == "RSDB") {
        if (entry.dataset_type == "raster") {
            CatalogEntryMetadata metadata("gdal_source",
                                          composeRSDBRasterMetadata(
                                                  user,
                                                  entry,
                                                  getRSDBRasterMetadata(entry.dataset_url, json_web_token)
                                          ));
            return metadata.toJson();
        } else if (entry.dataset_type == "vector") {
            CatalogEntryMetadata metadata("ogr_source",
                                          composeRSDBVectorMetadata(
                                                  user,
                                                  entry,
                                                  getRSDBVectorMetadata(entry.dataset_url, json_web_token),
                                                  json_web_token
                                          ));
            return metadata.toJson();
        } else {
            return UNKNOWN();
        }
    } else {
        return UNKNOWN();
    }
}

auto Nature40Service::CatalogEntryMetadata::toJson() const -> Json::Value {
    Json::Value result(Json::objectValue);
    result["result"] = true;
    result["metadata"] = metadata;
    return result;
}

auto Nature40Service::getRSDBRasterMetadata(const std::string &url, const std::string &json_web_token) const -> Json::Value {
    auto query = concat(url, "/meta.json?jws=", json_web_token);

    cURL curl;
    std::stringstream data;

    curl.setOpt(CURLOPT_PROXY, Configuration::get<std::string>("proxy", "").c_str());
    curl.setOpt(CURLOPT_URL, query.c_str());
    curl.setOpt(CURLOPT_WRITEFUNCTION, cURL::defaultWriteFunction);
    curl.setOpt(CURLOPT_WRITEDATA, &data);
    curl.setOpt(CURLOPT_FOLLOWLOCATION, 1L); // server sends 302 to data with cookie session
    curl.setOpt(CURLOPT_COOKIEFILE, ""); // forwards cookie to final request
    curl.perform();

    std::string json = data.str();

    Json::Reader reader(Json::Features::strictMode());
    Json::Value metadata;
    if (!reader.parse(json, metadata))
        throw std::runtime_error("Could not parse from RSDB Raster Metadata file");

    return metadata;
}

auto Nature40Service::composeRSDBRasterMetadata(UserDB::User &user, const CatalogEntry &entry,
                                                const Json::Value &metadata) const -> Json::Value {
    Json::Value result(Json::objectValue);

    std::string crs = metadata.get("ref", Json::objectValue).get("code", "").asString();

    Json::Value channels(Json::arrayValue);
    for (const auto &band : metadata.get("bands", Json::arrayValue)) {
        Json::Value channel(Json::objectValue);

        channel["name"] = band["title"];
        channel["datatype"] = band["datatype"];
        channel["crs"] = crs;

        channel["file_name"] = concat("/vsicurl_streaming/", // required for GDAL remote driver
                                      entry.dataset_url,
                                      "/raster.tiff?band=",
                                      band["index"].asInt(),
                                      "&ext=%%%MINX%%%%20%%%MINY%%%%20%%%MAXX%%%%20%%%MAXY%%%",
                                      "&width=%%%XRES%%%&height=%%%YRES%%%"
                                      "&JWS=%%%jwt:token%%%&clipped");

        // ugly hack to allow querying this raster
        user.addPermission(concat("data.gdal_source.", channel["file_name"].asString()));

        channel["channel"] = 1; // each tiff only has one band

        Unit mapping_unit = Unit::unknown();
        mapping_unit.setInterpolation(Unit::Interpolation::Continuous);
        mapping_unit.setMinMax(band["vis_min"].asInt(), band["vis_max"].asInt());
        channel["unit"] = mapping_unit.toJsonObject();

        channels.append(channel);
    }

    result["channels"] = channels;

    return result;
}

auto Nature40Service::getRSDBVectorMetadata(const std::string &url, const std::string &json_web_token) const -> Json::Value {
    auto query = concat(url, "?jws=", json_web_token);

    cURL curl;
    std::stringstream data;

    curl.setOpt(CURLOPT_PROXY, Configuration::get<std::string>("proxy", "").c_str());
    curl.setOpt(CURLOPT_URL, query.c_str());
    curl.setOpt(CURLOPT_WRITEFUNCTION, cURL::defaultWriteFunction);
    curl.setOpt(CURLOPT_WRITEDATA, &data);
    curl.setOpt(CURLOPT_FOLLOWLOCATION, 1L); // server sends 302 to data with cookie session
    curl.setOpt(CURLOPT_COOKIEFILE, ""); // forwards cookie to final request
    curl.perform();

    std::string json = data.str();

    Json::Reader reader(Json::Features::strictMode());
    Json::Value metadata;
    if (!reader.parse(json, metadata))
        throw std::runtime_error("Could not parse from RSDB Raster Metadata file");

    return metadata;
}

auto Nature40Service::composeRSDBVectorMetadata(UserDB::User &user,
                                                const Nature40Service::CatalogEntry &entry,
                                                const Json::Value &metadata,
                                                const std::string &json_web_token) const -> Json::Value {
    const Json::Value metadata_details = metadata.get("vectordb", Json::objectValue).get("details", Json::objectValue);

    // TODO: read epsg from metadata when OgrSource supports it
    // std::string epgs = metadata.get("details", Json::objectValue).get("epsg", "").asString();
    // std::string crs = concat("EPSG:", epgs.empty() ? "4326" : epgs);

    Json::Value ogr_source(Json::objectValue);
    ogr_source["operatorType"] = "ogr_source"; // type to de-serialize in WAVE
    // TODO: use original projection when OGRSource supports it
    ogr_source["dataset_id"] = concat(
            entry.dataset_url, "/geometry.json?epsg=4326",
            "&JWS=", json_web_token // TODO: integrate token placeholder in OgrSource
            );
    ogr_source["layer_id"] = "OGRGeoJSON"; // default `ogrinfo` name
    ogr_source["numeric"] = Json::arrayValue; // empty array since the db encodes everything as string
    ogr_source["textual"] = metadata_details.get("attributes", Json::arrayValue);

    Json::Value result(Json::objectValue);
    result["ogr_source"] = ogr_source;

    // ugly hack to allow querying this raster
    user.addPermission(concat("data.ogr_source.", ogr_source["dataset_id"].asString()));

    return result;
}
