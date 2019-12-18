/*  =========================================================================
    fty_nut_configuration_server - fty nut configuration actor

    Copyright (C) 2014 - 2018 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    fty_nut_configuration_server - fty nut configuration actor
@discuss
@end
*/

#include "fty_nut_classes.h"

#include <forward_list>
#include <regex>

namespace fty
{
namespace nut
{

constexpr int SCAN_TIMEOUT = 5;

/**
 * \brief Extract all IP addresses from an asset.
 * \param proto Asset to extract IP addresses from.
 * \return List of IP addresses as strings.
 */
std::vector<std::string> getNetworkAddressesFromAsset(fty_proto_t* asset)
{
    const static std::array<std::string, 2> prefixes = {
        "ip.",
        "ipv6."
    } ;

    // Fetch all network addresses.
    std::vector<std::string> addresses;
    for (const auto& prefix : prefixes) {
        const char* address;
        for (int i = 1; (address = fty_proto_ext_string(asset, (prefix + std::to_string(i)).c_str(), nullptr)); i++) {
            addresses.emplace_back(address);
        }
    }

    return addresses;
}

/**
 * \brief Scan asset for NUT driver configurations.
 *
 * The scan will detect the following drivers:
 * - netxml-ups
 * - snmp-ups (SNMPv1 and SNMPv3)
 * - snmp-ups-dmf (SNMPv1 and SNMPv3)
 *
 * \warning This won't return the list of all *working* NUT device configurations, as the list of handled NUT drivers is not exhaustive!
 *
 * \param pool PoolWorker to use.
 * \param asset fty_proto_t of asset to scan.
 * \param credentialsSnmpV1 SNMPv1 credentials to test.
 * \param credentialsSnmpV3 SNMPv3 credentials to test.
 * \return All detected and working NUT device configurations.
 */
nutcommon::DeviceConfigurations assetScanDrivers(messagebus::PoolWorker& pool, fty_proto_t *asset, const std::vector<nutcommon::CredentialsSNMPv1>& credentialsSnmpV1, const std::vector<nutcommon::CredentialsSNMPv3>& credentialsSnmpV3)
{
    nutcommon::DeviceConfigurations results;

    const auto addresses = getNetworkAddressesFromAsset(asset);

    std::forward_list<std::future<nutcommon::DeviceConfigurations>> futureResults;

    // Launch a bunch of scans in parallel.
    for (const auto& address : addresses) {
        nutcommon::ScanRangeOptions scanRangeOptions(address, SCAN_TIMEOUT);
        /// XXX: static_cast required because of deprecated functions creating overloaded functions.
        for (const auto& credential : credentialsSnmpV3) {
            futureResults.emplace_front(pool.schedule(static_cast<nutcommon::DeviceConfigurations(*)(const nutcommon::ScanRangeOptions&, const nutcommon::CredentialsSNMPv3&, bool)>(&nutcommon::scanDeviceRangeSNMPv3), scanRangeOptions, credential, false));
        }
        for (const auto& credential : credentialsSnmpV1) {
            futureResults.emplace_front(pool.schedule(static_cast<nutcommon::DeviceConfigurations(*)(const nutcommon::ScanRangeOptions&, const nutcommon::CredentialsSNMPv1&, bool)>(&nutcommon::scanDeviceRangeSNMPv1), scanRangeOptions, credential, false));
        }
        futureResults.emplace_front(pool.schedule(static_cast<nutcommon::DeviceConfigurations(*)(const nutcommon::ScanRangeOptions&)>(&nutcommon::scanDeviceRangeNetXML), scanRangeOptions));
    }

    /**
     * Grab all results.
     * FIXME: Rewrite with std::when_all once C++2x comes around.
     */
    for (auto& futureResult : futureResults) {
        auto result = futureResult.get();
        std::move(result.begin(), result.end(), std::back_inserter(results));
    }

    return results;
}

/**
 * \brief Extracts the fingerprint of a NUT device configuration.
 * \param configuration NUT device configuration.
 * \return NUT device configuration fingerprint.
 *
 * The generated extract uniquely identifies a NUT device configuration as far
 * as these properties are concerned:
 * - Driver type,
 * - Driver "subtype" (MIBs or whatever required information to access device),
 * - Port,
 * - Credentials.
 *
 * This allows reducing variants of a NUT device configuration to the same
 * driver fingerprint.
 *
 * \warning If a driver fingerprint is not recognized, the NUT device
 * configuration itself will be returned (which will uniquely identify itself).
 */
nutcommon::DeviceConfiguration extractConfigurationFingerprint(const nutcommon::DeviceConfiguration& configuration)
{
    nutcommon::DeviceConfiguration result;

    const static std::map<std::string, std::set<std::string>> fingerprintTemplates = {
        { "snmp-ups", {
            "driver", "port", "mibs", "snmp_version", "community", "secLevel", "secName", "authPassword", "authProtocol", "privPassword", "privProtocol"
        }},
        { "snmp-ups-dmf", {
            "driver", "port", "mibs", "snmp_version", "community", "secLevel", "secName", "authPassword", "authProtocol", "privPassword", "privProtocol"
        }},
        { "netxml-ups", {
            "driver", "port"
        }}
    };

    const auto& fingerprintTemplateIterator = fingerprintTemplates.find(configuration.at("driver"));
    if (fingerprintTemplateIterator != fingerprintTemplates.end()) {
        // Extract the template from the configuration.
        for (const auto& fingerprintKey : fingerprintTemplateIterator->second) {
            const auto &configurationKeyIterator = configuration.find(fingerprintKey);
            if (configurationKeyIterator != configuration.end()) {
                result[configurationKeyIterator->first] = configurationKeyIterator->second;
            }
        }
    }
    else {
        result = configuration;
    }

    return result;
}

/**
 * \brief Check if we can assess a NUT driver configuration's working state.
 * \param configuration NUT driver configuration to assess.
 * \return True if it is assessable.
 *
 * Only drivers we know about can be assessed, as only they will be scanned by
 * assetScanDrivers().
 */
bool canDeviceConfigurationWorkingStateBeAssessed(const nutcommon::DeviceConfiguration& configuration)
{
    const static std::set<std::string> knownDrivers = {
        "netxml-ups",
        "snmp-ups",
        "snmp-ups-dmf"
    } ;

    return knownDrivers.count(configuration.at("driver"));
}

struct ComputeAssetConfigurationUpdateResult {
    /// \brief Known, working configuration.
    nutcommon::DeviceConfigurations workingConfigurations;
    /// \brief Known, non-working configuration.
    nutcommon::DeviceConfigurations nonWorkingConfigurations;
    /// \brief Unknown, working configuration.
    nutcommon::DeviceConfigurations newConfigurations;
    /// \brief Unknown, unassessable configuration.
    nutcommon::DeviceConfigurations unknownStateConfigurations;
} ;

/**
 * \brief Sort NUT driver configurations into categories from known and detected configurations.
 * \param knownConfigurations Known NUT device configurations in database.
 * \param detectedConfigurations Detected NUT device configurations at runtime.
 * \return All NUT driver configurations sorted into categories.
 */
ComputeAssetConfigurationUpdateResult computeAssetConfigurationUpdate(const nutcommon::DeviceConfigurations& knownConfigurations, const nutcommon::DeviceConfigurations& detectedConfigurations)
{
    ComputeAssetConfigurationUpdateResult result;

    // Fingerprints of everything we detected.
    std::set<nutcommon::DeviceConfiguration> detectedFingerprints;
    std::transform(
        detectedConfigurations.begin(),
        detectedConfigurations.end(),
        std::inserter(detectedFingerprints, detectedFingerprints.begin()),
        extractConfigurationFingerprint
    );

    // Fingerprints we matched in the database.
    std::set<nutcommon::DeviceConfiguration> matchedFingerprints;

    for (const auto& knownConfiguration : knownConfigurations) {
        if (canDeviceConfigurationWorkingStateBeAssessed(knownConfiguration)) {
            // This is a known NUT driver, classify it as working or non-working.
            const auto& detectedFingerprintIterator = detectedFingerprints.find(extractConfigurationFingerprint(knownConfiguration));
            if (detectedFingerprintIterator != detectedFingerprints.end()) {
                // NUT driver configuration seems to work.
                result.workingConfigurations.push_back(knownConfiguration);

                matchedFingerprints.insert(*detectedFingerprintIterator);
            }
            else {
                // NUT driver configuration doesn't seem to work.
                result.nonWorkingConfigurations.push_back(knownConfiguration);
            }
        }
        else {
            // Unknown NUT driver configuration type.
            result.unknownStateConfigurations.push_back(knownConfiguration);
        }
    }

    /**
     * We classified known NUT device configurations, now we need to deal with
     * unknown and detected NUT device configurations.
     */
    std::set<nutcommon::DeviceConfiguration> unmatchedFingerprints;
    std::set_difference(
        detectedFingerprints.begin(), detectedFingerprints.end(),
        matchedFingerprints.begin(), matchedFingerprints.end(),
        std::inserter(unmatchedFingerprints, unmatchedFingerprints.begin())
    );

    for (const auto& detectedConfiguration : detectedConfigurations) {
        if (unmatchedFingerprints.count(extractConfigurationFingerprint(detectedConfiguration))) {
            // New and working device configuration.
            result.newConfigurations.push_back(detectedConfiguration);
        }
    }

    return result;
}

/**
 * \brief Check if device configuration is a subset of another.
 * \param subset Device configuration subset.
 * \param superset Device configuration superset.
 * \return True iff subset of superset.
 */
bool isDeviceConfigurationSubsetOf(const nutcommon::DeviceConfiguration& subset, const nutcommon::DeviceConfiguration& superset)
{
    for (const auto& itSubset : subset) {
        // Field "desc" is not important, skip it.
        if (itSubset.first == "desc") {
            continue;
        }

        auto itSuperset = superset.find(itSubset.first);
        if (itSuperset == superset.end() || itSubset != (*itSuperset)) {
            return false;
        }
    }

    return true;
}

/**
 * \brief Instanciate a device configuration template from a device.
 *
 * Device configuration templates can contain values derived from the asset with the following syntax:
 * - ${aux.<auxiliary property key>}
 * - ${ext.<extended property key>}
 *
 * \param asset Asset to instanciate from.
 * \param template Device configuration template.
 * \return Instanciated device configuration template, or empty device configuration on error.
 */
nutcommon::DeviceConfiguration instanciateDeviceConfigurationFromTemplate(fty_proto_t* asset, const nutcommon::DeviceConfiguration& confTemplate)
{
    nutcommon::DeviceConfiguration result;

    // Instanciate each property in the template.
    for (const auto& property : confTemplate) {
        const static std::regex token(R"xxx(\$\{([^}]+)\})xxx", std::regex::optimize);
        std::string templatedValue = property.second;
        std::smatch matches;

        while (std::regex_search(templatedValue, matches, token)) {
            // We need to template the property value.
            auto str = matches[1].str();

            // Try to instanciate value.
            const char* value = nullptr;
            if (str.find_first_of("asset.ext.") == 0) {
                value = fty_proto_ext_string(asset, str.c_str()+10, nullptr);
            }
            else if (str.find_first_of("asset.aux.") == 0) {
                value = fty_proto_aux_string(asset, str.c_str()+10, nullptr);
            }

            // Bail out if value wasn't found.
            if (!value) {
                return {};
            }

            templatedValue.replace(matches.position(1)-2, matches.length(1)+3, value);
        }

        result.emplace(property.first, templatedValue);
    }

    return result;
}

std::vector<size_t> sortDeviceConfigurationPreferred(const nutcommon::DeviceConfigurations& configurations, fty_proto_t* asset) {
    // Initialize vector of indexes.
    std::vector<size_t> indexes(configurations.size());
    std::iota(indexes.begin(), indexes.end(), 0);

    std::sort(indexes.begin(), indexes.end(), [&configurations, &asset](size_t a, size_t b) {
        /**
         * This is a fairly complicated sort function. Here, we try to return
         * true iff confA is worse than confB.
         *
         * This to keep in mind:
         * - std::sort expects a total order.
         * - Total sort means if we return true for a condition, we must return false in the "mirror" condition.
         */
        const std::string type = fty_proto_type(asset);
        const auto& confA = configurations[a];
        const auto& confB = configurations[b];

        auto isConfSnmp =   [](const nutcommon::DeviceConfiguration& conf) -> bool { return conf.at("driver").find_first_of("snmp-ups") == 0; } ;
        auto isConfNetXML = [](const nutcommon::DeviceConfiguration& conf) -> bool { return conf.at("driver") == "netxml-ups"; } ;
        auto confSnmpVersion = [&isConfSnmp](const nutcommon::DeviceConfiguration& conf) -> int {
            if (!isConfSnmp(conf)) { return -1; }
            auto snmp_version = conf.find("snmp_version");
            if (snmp_version == conf.end() || snmp_version->second == "v1") { return 1; }
            else if (snmp_version->second == "v2c") { return 2; }
            else if (snmp_version->second == "v3") { return 3; }
            else { return 0; }
        } ;
        auto confSnmpMib =  [](const nutcommon::DeviceConfiguration& conf) -> std::string {
            return conf.count("mibs") > 0 ? conf.at("mibs") : "auto";
        } ;
        auto confSnmpSec =  [](const nutcommon::DeviceConfiguration& conf) -> std::string {
            return conf.count("secLevel") > 0 ? conf.at("secLevel") : "noAuthNoPriv";
        } ;
        auto confSnmpCom =  [](const nutcommon::DeviceConfiguration& conf) -> std::string {
            return conf.count("community") > 0 ? conf.at("community") : "public";
        } ;

        const bool isConfA_SNMP = isConfSnmp(confA);
        const bool isConfB_SNMP = isConfSnmp(confB);
        const int confA_SNMP_version = confSnmpVersion(confA);
        const int confB_SNMP_version = confSnmpVersion(confB);
        const std::string confA_SNMP_security = confSnmpSec(confA);
        const std::string confB_SNMP_security = confSnmpSec(confB);
        const std::string confA_SNMP_community = confSnmpCom(confA);
        const std::string confB_SNMP_community = confSnmpCom(confB);
        const std::string confA_SNMP_mib = confSnmpMib(confA);
        const std::string confB_SNMP_mib = confSnmpMib(confB);
        const bool isConfA_NetXML = confA.at("driver") == "netxml-ups";
        const bool isConfB_NetXML = confB.at("driver") == "netxml-ups";
        const static std::array<std::string, 2> snmpMibPriority = { "mge", "pw" };
        const static std::array<std::string, 3> snmpSecPriority = { "noAuthNoPriv", "authNoPriv", "authPriv" };

        if (type == "ups") {
            // Prefer NetXML over SNMP.
            if (isConfB_NetXML && isConfA_SNMP) { return true; }
            if (isConfA_NetXML && isConfB_SNMP) { return false; }
        }
        else if (type == "epdu" || type == "pdu" || type == "sts") {
            // Prefer SNMP over NetXML.
            if (isConfB_SNMP && isConfA_NetXML) { return true; }
            if (isConfA_SNMP && isConfB_NetXML) { return false; }
        }

        // SNMP preferences.
        if (isConfA_SNMP && isConfB_SNMP) {
            // Prefer most recent SNMP version.
            if (confA_SNMP_version != confB_SNMP_version) { return confA_SNMP_version < confB_SNMP_version; }
            // Prefer most secure SNMPv3 security level.
            const auto confA_SNMP_priority_sec = std::find(snmpSecPriority.begin(), snmpSecPriority.end(), confA_SNMP_security);
            const auto confB_SNMP_priority_sec = std::find(snmpSecPriority.begin(), snmpSecPriority.end(), confB_SNMP_security);
            if (confA_SNMP_priority_sec != confB_SNMP_priority_sec) { return confA_SNMP_priority_sec < confB_SNMP_priority_sec; }
            // Perfer some MIBs over others.
            const auto confA_SNMP_priority_mib = std::find(snmpMibPriority.begin(), snmpMibPriority.end(), confA_SNMP_mib);
            const auto confB_SNMP_priority_mib = std::find(snmpMibPriority.begin(), snmpMibPriority.end(), confB_SNMP_mib);
            if (confA_SNMP_priority_mib != confB_SNMP_priority_mib) { return confA_SNMP_priority_mib < confB_SNMP_priority_mib; }
            // Prefer other communities than public.
            if (confA_SNMP_community == "public" && confB_SNMP_community != "public") { return true; }
            if (confA_SNMP_community != "public" && confB_SNMP_community == "public") { return false; }
        }

        // Fallback.
        return confA < confB;
    });

    // We sorted from worst to best configurations, must reverse to get best to worst configurations.
    std::reverse(indexes.begin(), indexes.end());

    return indexes;
}

// matchDeviceConfigurationToBestDeviceConfigurationType(const nutcommon::DeviceConfiguration& configuration)

// ConfigurationManager

ConfigurationManager::ConfigurationManager() : m_poolScanners(8)
{
}

void ConfigurationManager::scanAssetConfigurations(const std::string& assetName)
{
#if 0
    fty_proto_t *asset = //;
    if (!asset) {
        throw std::runtime_error("Unknown asset");
    }

    auto detectedConfigurations = assetScanDrivers(m_poolScanners, asset, nutcommon::getCredentialsSNMPv1(), nutcommon::getCredentialsSNMPv3());
    auto results = computeAssetConfigurationUpdate({}, detectedConfigurations);

    /**
     * Write debug logs of computeAssetConfigurationUpdate().
     */
    std::stringstream ss;
    for (const auto& result : std::vector<std::pair<const char*, const nutcommon::DeviceConfigurations&>>({
        { "Working configurations:", results.workingConfigurations },
        { "Non-working configurations:", results.nonWorkingConfigurations },
        { "New configurations:", results.newConfigurations },
        { "Unknown state configurations:", results.unknownStateConfigurations },
    })) {
        ss << result.first << std::endl;
        for (const auto &configuration : result.second) {
            ss << configuration << std::endl;
        }
    }
    log_debug("Summary of device configurations after scan for asset %s:\n%s", ss.str().c_str(), assetName.c_str(), ss.str().c_str());

    /**
     * Update known driver configurations in database.
     */
    for (const auto& updateOrder : std::vector<std::pair<const nutcommon::DeviceConfigurations&, bool>>({
        { results.workingConfigurations, true },
        { results.unknownStateConfigurations, true },
        { results.nonWorkingConfigurations, false },
    })) {
        for (const auto& configuration : updateOrder.first) {
            // TODO: Match configuration to what's in DB...
            log_trace("Marking device configuration ID %u as %s.", 0, updateOrder.second ? "working" : "non-working");
        }
    }

    /**
     * TODO: Register new configurations in database.
     */
    if (!results.newConfigurations.empty()) {
        auto deviceConfigurationTypes = ...;
        for (const auto& newConfiguration : results.newConfigurations) {
            for (const auto& deviceConfigurationType : deviceConfigurationTypes) {
                auto instanciatedDeviceConfiguration = instanciateDeviceConfigurationFromTemplate(asset, deviceConfigurationType);
                if (instanciatedDeviceConfiguration.empty()) {
                    continue;
                }

                if (isDeviceConfigurationSubsetOf(instanciatedDeviceConfiguration))
            }
        }
    }

    /**
     * XXX: Sort priorities of asset's driver configurations.
     * Must be removed once user has control of driver configurations!
     */
#endif
}

// ConfigurationConnector

ConfigurationConnector::Parameters::Parameters() :
    endpoint(MLM_ENDPOINT),
    agentName("fty-nut-configuration"),
    dbUrl(DBConn::url)
{
}

ConfigurationConnector::ConfigurationConnector(ConfigurationConnector::Parameters params) :
    m_parameters(params),
    m_manager(),
    m_dispatcher({
    }),
    m_worker(0),
    m_msgBus(messagebus::MlmMessageBus(params.endpoint, params.agentName))
{
    m_msgBus->connect();
    m_msgBus->receive("ETN.Q.IPMCORE.NUTCONFIGURATION", std::bind(&ConfigurationConnector::handleRequest, this, std::placeholders::_1));
}

void ConfigurationConnector::handleRequest(messagebus::Message msg) {
    if ((msg.metaData().count(messagebus::Message::SUBJECT) == 0) ||
        (msg.metaData().count(messagebus::Message::COORELATION_ID) == 0) ||
        (msg.metaData().count(messagebus::Message::REPLY_TO) == 0)) {
        log_error("Missing subject/correlationID/replyTo in request.");
    }
    else {
        m_worker.offload([this](messagebus::Message msg) {
            auto subject = msg.metaData()[messagebus::Message::SUBJECT];
            auto corrId = msg.metaData()[messagebus::Message::COORELATION_ID];
            log_info("Received %s (%s) request.", subject.c_str(), corrId.c_str());

            try {
                auto result = m_dispatcher(subject, msg.userData());

                log_info("Request %s (%s) performed successfully.", subject.c_str(), corrId.c_str());
                sendReply(msg.metaData(), true, result);
            }
            catch (std::exception& e) {
                log_error("Exception while processing %s (%s): %s", subject.c_str(), corrId.c_str(), e.what());
                sendReply(msg.metaData(), false, { e.what() });
            }
        }, std::move(msg));
    }
}

void ConfigurationConnector::sendReply(const messagebus::MetaData& metadataRequest, bool status, const messagebus::UserData& dataReply) {
    messagebus::Message reply;

    reply.metaData() = {
        { messagebus::Message::COORELATION_ID, metadataRequest.at(messagebus::Message::COORELATION_ID) },
        { messagebus::Message::SUBJECT, metadataRequest.at(messagebus::Message::SUBJECT) },
        { messagebus::Message::STATUS, status ? "ok" : "ko" },
        { messagebus::Message::TO, metadataRequest.at(messagebus::Message::REPLY_TO) }
    } ;
    reply.userData() = dataReply;

    m_msgBus->sendReply("ETN.R.IPMCORE.POWERACTION", reply);
}

}
}

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
fty_nut_configuration_server_test (bool verbose)
{
    std::cerr << " * fty_nut_configuration_server: " << std::endl;

    {
        struct TestCase {
            nutcommon::DeviceConfigurations knownConfigurations;
            nutcommon::DeviceConfigurations detectedConfigurations;

            /**
             * - Working
             * - Non-working
             * - New
             * - Unknown
             */
            fty::nut::ComputeAssetConfigurationUpdateResult expectedResult;
        };

        const std::vector<TestCase> testCases = {
            // No known configuration, everything detected should be new configurations.
            TestCase({
                {},
                nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="noAuthNoPriv",secName="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES"
)xxx"),

                fty::nut::ComputeAssetConfigurationUpdateResult({
                    {},
                    {},
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="noAuthNoPriv",secName="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES"
)xxx"),
                    {},
                }),
            }),

            // Test all cases with non-overlapping fingerprints.
            TestCase({
                nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private"
SNMP:driver="dummy-ups",port="10.130.33.140"
)xxx"),
                nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="suprise"
)xxx"),

                fty::nut::ComputeAssetConfigurationUpdateResult({
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="suprise"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="dummy-ups",port="10.130.33.140"
)xxx"),
                }),
            }),


            // Test all cases with overlapping fingerprints.
            TestCase({
                nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra",woohoo="woohoo"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private",extra="extra",woohoo="woohoo"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="privateer",extra="extra"
SNMP:driver="dummy-ups",port="10.130.33.140"
)xxx"),
                nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="privateer"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="suprise"
)xxx"),

                fty::nut::ComputeAssetConfigurationUpdateResult({
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra",woohoo="woohoo"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="privateer",extra="extra"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private",extra="extra",woohoo="woohoo"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="suprise"
)xxx"),
                    nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="dummy-ups",port="10.130.33.140"
)xxx"),
                }),
            }),
        };

        for (int i = 0; i < testCases.size(); i++) {
            std::cerr << "  - computeAssetConfigurationUpdate case #" << (i+1) << ": ";
            const TestCase& testCase = testCases[i];

            auto result = fty::nut::computeAssetConfigurationUpdate(testCase.knownConfigurations, testCase.detectedConfigurations);
            for (const auto& it : std::vector<std::pair<const nutcommon::DeviceConfigurations&, const nutcommon::DeviceConfigurations&>>({
                { result.workingConfigurations,         testCase.expectedResult.workingConfigurations },
                { result.nonWorkingConfigurations,      testCase.expectedResult.nonWorkingConfigurations },
                { result.newConfigurations,             testCase.expectedResult.newConfigurations },
                { result.unknownStateConfigurations,    testCase.expectedResult.unknownStateConfigurations },
            })) {
                const std::set<nutcommon::DeviceConfiguration> resultSorted(it.first.begin(), it.first.end());
                const std::set<nutcommon::DeviceConfiguration> expectedSorted(it.second.begin(), it.second.end());
                assert(resultSorted == expectedSorted);
                std::cerr << resultSorted.size() << " ";
            }

            std::cerr << "OK" << std::endl;
        }
    }

    {
        std::cerr << "  - isDeviceConfigurationSubsetOf: ";

        const auto supersetConfigurations = nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public",extra="extra",woohoo="woohoo"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="privateer",extra="extra"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="noAuthNoPriv",secName="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="-----------------------------------",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES",extra="extra"
)xxx");
        const auto subsetConfigurations = nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="noAuthNoPriv",secName="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES"
)xxx");
        const auto expectedResults = std::vector<std::pair<const nutcommon::DeviceConfiguration&, std::array<bool, 7>>> {
            { subsetConfigurations[0], {
                true, true, true, false, false, false, false
            }},
            { subsetConfigurations[1], {
                false, false, false, false, true, false, false
            }},
            { subsetConfigurations[2], {
                false, false, false, false, false, true, true
            }},
        } ;

        for (const auto& expectedResult : expectedResults) {
            for (size_t i = 0; i < supersetConfigurations.size(); i++) {
                assert(fty::nut::isDeviceConfigurationSubsetOf(expectedResult.first, supersetConfigurations[i]) == expectedResult.second[i]);
            }
        }

        std::cerr << "OK" << std::endl;
    }

    {
        std::cerr << "  - instanciateDeviceConfigurationFromTemplate: ";
        fty_proto_t* asset = fty_proto_new(FTY_PROTO_ASSET);
        fty_proto_ext_insert(asset, "ipv4.1", "10.130.32.117");
        fty_proto_ext_insert(asset, "snmp_port", "161");

        const static auto templateConf = nutcommon::DeviceConfiguration {
            { "driver", "snmp-ups" },
            { "port", "${asset.ext.ipv4.1}" },
            { "port-snmp", "snmp://${asset.ext.ipv4.1}:${asset.ext.snmp_port}/" },
        };
        const static auto expectedResult = nutcommon::DeviceConfiguration {
            { "driver", "snmp-ups" },
            { "port", "10.130.32.117" },
            { "port-snmp", "snmp://10.130.32.117:161/" },
        };
        const auto result = fty::nut::instanciateDeviceConfigurationFromTemplate(asset, templateConf);
        assert(result == expectedResult);

        const static auto expectedFailures = std::vector<nutcommon::DeviceConfiguration> {
            {
                { "driver", "snmp-ups" },
                { "port", "${asset.ext.ipv4.2}" },
            },
            {
                { "driver", "snmp-ups" },
                { "port", "${idunno}" },
            },
        };
        for (const auto& expectedFailure : expectedFailures) {
            const auto result = fty::nut::instanciateDeviceConfigurationFromTemplate(asset, expectedFailure);
            assert(result.empty());
        }

        fty_proto_destroy(&asset);
        std::cerr << "OK" << std::endl;
    }

    {
        std::cerr << "  - sortDeviceConfigurationPreferred: ";

        const auto configurations = nutcommon::parseScannerOutput(
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="public"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="authPriv",secName="private",authPassword="azertyui",privPassword="qsdfghjk",authProtocol="MD5",privProtocol="DES"
XML:driver="netxml-ups",port="http://10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19"
SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",snmp_version="v3",secLevel="noAuthNoPriv",secName="public"
R"xxx(SNMP:driver="snmp-ups",port="10.130.33.140",desc="EPDU MA 0U (C20 16A 1P)20XC13:4XC19",mibs="eaton_epdu",community="private"
)xxx");
        const static std::vector<size_t> expectedUpsResult = { 2, 1, 3, 4, 0 } ;
        const static std::vector<size_t> expectedEpduResult = { 1, 3, 4, 0, 2 } ;

        fty_proto_t* upsAsset = fty_proto_new(FTY_PROTO_ASSET);
        fty_proto_set_type(upsAsset, "ups");
        fty_proto_t* epduAsset = fty_proto_new(FTY_PROTO_ASSET);
        fty_proto_set_type(epduAsset, "epdu");

        const auto upsResult = fty::nut::sortDeviceConfigurationPreferred(configurations, upsAsset);
        const auto epduResult = fty::nut::sortDeviceConfigurationPreferred(configurations, epduAsset);
        assert(upsResult == expectedUpsResult);
        assert(epduResult == expectedEpduResult);

        fty_proto_destroy(&epduAsset);
        fty_proto_destroy(&upsAsset);
        std::cerr << "OK" << std::endl;
    }
}
