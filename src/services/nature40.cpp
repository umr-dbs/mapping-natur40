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

        static constexpr const char *EXTERNAL_ID_PREFIX = "JWT:";

        void run() override;

        auto queryCatalog(const std::string &token) -> std::vector<CatalogEntry>;

        auto createCatalogSession(const std::string &token) const -> std::string;

        auto getCatalogJSON(const std::string &sessionId) const -> Json::Value;
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
