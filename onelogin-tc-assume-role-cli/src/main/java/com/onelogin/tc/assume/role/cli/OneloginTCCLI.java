package com.onelogin.tc.assume.role.cli;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.sdk.conn.Client;
import com.onelogin.sdk.model.Device;
import com.onelogin.sdk.model.MFA;
import com.onelogin.sdk.model.SAMLEndpointResponse;
import com.tencentcloudapi.common.Credential;
import com.tencentcloudapi.sts.v20180813.StsClient;
import com.tencentcloudapi.sts.v20180813.models.AssumeRoleWithSAMLRequest;
import com.tencentcloudapi.sts.v20180813.models.AssumeRoleWithSAMLResponse;
import com.tencentcloudapi.sts.v20180813.models.Credentials;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class OneloginTCCLI {

    private static int time = 45;
    private static int loop = 1;
    private static String profileName = null;
    private static String oneloginUsernameOrEmail = null;
    private static String oneloginPassword = null;
    private static String appId = null;
    private static String oneloginDomain = null;
    private static String tcRegion = null;
    private static String tcAccountId = null;
    private static String tcRoleName = null;
    private static int duration = 900;
    private static String oneloginClientID = null;
    private static String oneloginClientSecret = null;
    private static String oneloginRegion = "us";
    private static String ip = null;
    private static Integer samlApiVersion = 1;
    private static String defaultTCRegion = "ap-guangzhou";

    public static Boolean commandParser(final String[] commandLineArguments) {
        final CommandLineParser cmd = new DefaultParser();
        final Options options = buildOptions();
        CommandLine commandLine;
        try {
            commandLine = cmd.parse(options, commandLineArguments);
            String value;

            if (commandLine.hasOption("help")) {
                HelpFormatter hf = new HelpFormatter();
                hf.printHelp("onelogin-tc-cli.jar [options]", options);
                System.out.println("");
                return false;
            }

            if (commandLine.hasOption("time")) {
                value = commandLine.getOptionValue("time");
                if (value != null && !value.isEmpty()) {
                    time = Integer.parseInt(value);
                }
                if (time < 15) {
                    time = 15;
                }
                if (time > 60) {
                    time = 60;
                }
            }
            if (commandLine.hasOption("loop")) {
                value = commandLine.getOptionValue("loop");
                if (value != null && !value.isEmpty()) {
                    loop = Integer.parseInt(value);
                }
            }
            if (commandLine.hasOption("profile")) {
                value = commandLine.getOptionValue("profile");
                if (value != null && !value.isEmpty()) {
                    profileName = value;
                } else {
                    profileName = "default";
                }
            }

            if (commandLine.hasOption("username")) {
                value = commandLine.getOptionValue("username");
                if (value != null && !value.isEmpty()) {
                    oneloginUsernameOrEmail = value;
                }
            }

            if (commandLine.hasOption("subdomain")) {
                value = commandLine.getOptionValue("subdomain");
                if (value != null && !value.isEmpty()) {
                    oneloginDomain = value;
                }
            }

            if (commandLine.hasOption("appid")) {
                value = commandLine.getOptionValue("appid");
                if (value != null && !value.isEmpty()) {
                    appId = value;
                }
            }

            if (commandLine.hasOption("region")) {
                value = commandLine.getOptionValue("region");
                if (value != null && !value.isEmpty()) {
                    tcRegion = value;
                }
            }

            if (commandLine.hasOption("password")) {
                value = commandLine.getOptionValue("password");
                if (value != null && !value.isEmpty()) {
                    oneloginPassword = value;
                }
            }

            if (commandLine.hasOption("tc-account-id")) {
                value = commandLine.getOptionValue("tc-account-id");
                if (value != null && !value.isEmpty()) {
                    tcAccountId = value;
                }
            }

            if (commandLine.hasOption("tc-role-name")) {
                value = commandLine.getOptionValue("tc-role-name");
                if (value != null && !value.isEmpty()) {
                    tcRoleName = value;
                }
            }

            if (commandLine.hasOption("duration")) {
                value = commandLine.getOptionValue("duration");
                if (value != null && !value.isEmpty()) {
                    duration = Integer.parseInt(value);
                }
                if (duration < 900) {
                    duration = 900;
                } else if (duration > 43200) {
                    duration = 900;
                }
            } else {
                duration = 900;
            }

            if (commandLine.hasOption("onelogin-client-id")) {
                value = commandLine.getOptionValue("onelogin-client-id");
                if (value != null && !value.isEmpty()) {
                    oneloginClientID = value;
                }
            }

            if (commandLine.hasOption("onelogin-client-secret")) {
                value = commandLine.getOptionValue("onelogin-client-secret");
                if (value != null && !value.isEmpty()) {
                    oneloginClientSecret = value;
                }
            }

            if (commandLine.hasOption("onelogin-region")) {
                value = commandLine.getOptionValue("onelogin-region");
                if (value != null && !value.isEmpty()) {
                    oneloginRegion = value;
                }
            }

            if (commandLine.hasOption("ip")) {
                value = commandLine.getOptionValue("ip");
                if (value != null && !value.isEmpty()) {
                    ip = value;
                }
            }

            if (commandLine.hasOption("saml-api-version")) {
                value = commandLine.getOptionValue("saml-api-version");
                if (value != null && !value.isEmpty()) {
                    samlApiVersion = Integer.parseInt(value);
                }
                if (samlApiVersion < 1) {
                    samlApiVersion = 1;
                } else if (samlApiVersion > 2) {
                    samlApiVersion = 2;
                }
            }

            // VALIDATIONS

            if (((tcAccountId != null && !tcAccountId.isEmpty()) && (tcRoleName == null || tcRoleName.isEmpty())) || ((tcRoleName != null && !tcRoleName.isEmpty()) && (tcAccountId == null || tcAccountId.isEmpty()))) {
                System.err.println("--tc-account-id and --tc-role-name need to be set together");
                return false;
            }

            if (((oneloginClientID != null && !oneloginClientID.isEmpty()) && (oneloginClientSecret == null || oneloginClientSecret.isEmpty())) || ((oneloginClientSecret != null && !oneloginClientSecret.isEmpty()) && (oneloginClientID == null || oneloginClientID.isEmpty()))) {
                System.err.println("--onelogin-client-id and --onelogin-client-secret need to be set together");
                return false;
            }
            return true;
        } catch (ParseException parseException) {
            System.err.println("Encountered exception while parsing" + parseException.getMessage());
            return false;
        }
    }

    public static Options buildOptions() {
        final Options options = new Options();
        options.addOption("h", "help", false, "Show the help guide");
        options.addOption("t", "time", true, "Sleep time between iterations, in minutes  [15-60 min]");
        options.addOption("l", "loop", true, "Number of iterations");
        options.addOption("p", "profile", true, "Save temporary TencentCloud credentials using that profile name");
        options.addOption("r", "region", true, "Set the TencentCloud region.");
        options.addOption("a", "appid", true, "Set TencentCloud App ID.");
        options.addOption("d", "subdomain", true, "OneLogin Instance Sub Domain.");
        options.addOption("u", "username", true, "OneLogin username.");
        options.addOption(null, "password", true, "OneLogin password.");
        options.addOption(null, "tc-account-id", true, "TencentCloud Account ID.");
        options.addOption(null, "tc-role-name", true, "TencentCloud Role Name.");
        options.addOption("z", "duration", true, "Desired TencentCloud Credential Duration");
        options.addOption(null, "onelogin-client-id", true, "A valid OneLogin API client_id");
        options.addOption(null, "onelogin-client-secret", true, "A valid OneLogin API client_secret");
        options.addOption(null, "onelogin-region", true, "Onelogin region. us or eu  (Default value: us)");
        options.addOption(null, "ip", true, "The IP address to use for the SAML assertion");
        options.addOption(null, "saml-api-version", true, "The version of the OneLogin SAML APIs to use (Default value 1)");

        return options;
    }

    public static void main(String[] commandLineArguments) throws Exception {

        System.out.println("\nOneLogin TencentCloud Assume Role Tool\n");

        if (!commandParser(commandLineArguments)) {
            return;
        }

        // OneLogin Java SDK Client
        Client olClient;
        if ((oneloginClientID == null || oneloginClientID.isEmpty()) && (oneloginClientSecret == null || oneloginClientSecret.isEmpty())) {
            olClient = new Client();
        } else {
            olClient = new Client(oneloginClientID, oneloginClientSecret, oneloginRegion);
        }

        // Set the version of the OneLogin SAML API to use
        HashMap<String, Integer> apic = new HashMap<String, Integer>();
        apic.put("assertion", samlApiVersion);
        olClient.setApiConfiguration(apic);

        if (ip == null) {
            ip = olClient.getIP();
        }
        olClient.getAccessToken();
        Scanner scanner = new Scanner(System.in);
        int currentDuration = duration;
        try {
            String samlResponse;

            Map<String, String> mfaVerifyInfo = null;
            Map<String, Object> result;

            String roleArn = null;
            String principalArn = null;

            for (int i = 0; i < loop; i++) {
                if (i == 0) {
                    // Capture OneLogin Account Details
                    System.out.print("OneLogin Username: ");
                    if (oneloginUsernameOrEmail == null) {
                        oneloginUsernameOrEmail = scanner.next();
                    } else {
                        System.out.println(oneloginUsernameOrEmail);
                    }

                    if (oneloginPassword == null) {
                        System.out.print("OneLogin Password: ");
                        try {
                            oneloginPassword = String.valueOf(System.console().readPassword());
                        } catch (Exception e) {
                            oneloginPassword = scanner.next();
                        }
                    }
                    System.out.print("TencentCloud App ID: ");
                    if (appId == null) {
                        appId = scanner.next();
                    } else {
                        System.out.println(appId);
                    }

                    System.out.print("Onelogin Instance Sub Domain: ");
                    if (oneloginDomain == null) {
                        oneloginDomain = scanner.next();
                    } else {
                        System.out.println(oneloginDomain);
                    }
                } else {
                    TimeUnit.MINUTES.sleep(time);
                }

                result = getSamlResponse(olClient, scanner, oneloginUsernameOrEmail, oneloginPassword, appId,
                        oneloginDomain, mfaVerifyInfo, ip);
                mfaVerifyInfo = (Map<String, String>) result.get("mfaVerifyInfo");
                samlResponse = (String) result.get("samlResponse");

                if (i == 0) {
                    HttpRequest simulatedRequest = new HttpRequest("http://example.com");
                    simulatedRequest = simulatedRequest.addParameter("SAMLResponse", samlResponse);
                    SamlResponse samlResponseObj = new SamlResponse(new SettingsBuilder().build(), simulatedRequest);
                    HashMap<String, List<String>> attributes = samlResponseObj.getAttributes();
                    if (!attributes.containsKey("https://cloud.tencent.com/SAML/Attributes/Role")) {
                        System.out.print("SAMLResponse from Identity Provider does not contain TencentCloud Role info");
                        System.exit(0);
                    } else {
                        String selectedRole = "";
                        List<String> roleDataList = attributes.get("https://cloud.tencent.com/SAML/Attributes/Role");
                        List<String> roleData = new ArrayList<String>();

                        for (int j = 0; j < roleDataList.size(); j++) {
                            String[] rolesAndPrinciples = roleDataList.get(j).split(",");
                            String rolesString = rolesAndPrinciples[0];
                            String principle = rolesAndPrinciples[1];
                            String[] roles = rolesString.split(";");
                            for (int k = 0; k < roles.length; k++) {
                                String role = roles[k];
                                if (tcAccountId != null && !role.split(":")[4].equals("uin/" + tcAccountId))
                                    continue;
                                if (!role.split(":")[5].startsWith("roleName"))
                                    continue;
                                roleData.add(roles[k] + "," + principle);
                            }
                        }

                        if (roleData.size() == 1 && !roleData.get(0).isEmpty()) {
                            String[] roleInfo = roleData.get(0).split(",")[0].split(":");
                            String accountId = roleInfo[4].replace("uin/", "");
                            String roleName = roleInfo[5].replace("roleName/", "");
                            System.out.println("Role selected: " + roleName + " (Account " + accountId + ")");
                            selectedRole = roleData.get(0);
                        } else if (roleData.size() > 1) {
                            roleData.sort(new Comparator<String>() {
                                @Override
                                public int compare(String s1, String s2) {
                                    String name1 = s1.split(":")[5];
                                    String name2 = s2.split(":")[5];
                                    List<String> names = new ArrayList<>();
                                    if (name1 == name2) {
                                        return 0;
                                    }
                                    names.add(name1);
                                    names.add(name2);
                                    Collections.sort(names);
                                    if (names.get(0) == name1) {
                                        return -1;
                                    } else {
                                        return 1;
                                    }
                                }
                            });
                            System.out.println("\nAvailable TencentCloud Roles");
                            System.out.println("-----------------------------------------------------------------------");
                            Map<String, Map<String, Integer>> rolesByApp = new HashMap<String, Map<String, Integer>>();
                            Map<String, Integer> val = null;
                            for (int j = 0; j < roleData.size(); j++) {
                                String[] roleInfo = roleData.get(j).split(",")[0].split(":");
                                String accountId = roleInfo[4].replace("uin/", "");
                                String roleName = roleInfo[5].replace("roleName/", "");
                                System.out.println(" " + j + " | " + roleName + " (Account " + accountId + ")");
                                if (rolesByApp.containsKey(accountId)) {
                                    rolesByApp.get(accountId).put(roleName, j);
                                } else {
                                    val = new HashMap<String, Integer>();
                                    val.put(roleName, j);
                                    rolesByApp.put(accountId, val);
                                }
                            }

                            Integer roleSelection = null;
                            if (tcAccountId != null && tcRoleName != null && rolesByApp.containsKey(tcAccountId) && rolesByApp.get(tcAccountId).containsKey(tcRoleName)) {
                                roleSelection = rolesByApp.get(tcAccountId).get(tcRoleName);
                            }

                            if (roleSelection == null) {
                                if (tcAccountId != null && !tcAccountId.isEmpty() && tcRoleName != null && !tcRoleName.isEmpty()) {
                                    System.out.println("SAMLResponse from Identity Provider does not contain available TencentCloud Role: " + tcAccountId + " for TencentCloud Account: " + tcRoleName);
                                }
                                System.out.println("-----------------------------------------------------------------------");
                                System.out.print("Select the desired Role [0-" + (roleData.size() - 1) + "]: ");
                                roleSelection = getSelection(scanner, roleData.size());
                            }
                            selectedRole = roleData.get(roleSelection);
                        } else {
                            System.out.print("SAMLResponse from Identity Provider does not contain available TencentCloud Role for this user");
                            System.exit(0);
                        }

                        if (!selectedRole.isEmpty()) {
                            String[] selectedRoleData = selectedRole.split(",");
                            roleArn = selectedRoleData[0];
                            principalArn = selectedRoleData[1];
                        }
                    }
                }

                if (i == 0) {
                    // TencentCloud REGION
                    if (tcRegion == null) {
                        System.out.print("TencentCloud Region (" + defaultTCRegion + "): ");
                        tcRegion = scanner.next();
                        if (tcRegion.isEmpty() || tcRegion.equals("-")) {
                            tcRegion = defaultTCRegion;
                        }
                    } else {
                        System.out.print("TencentCloud Region: " + tcRegion);
                    }
                }

                StsClient stsClient = new StsClient(new Credential(), tcRegion);

                AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest = new AssumeRoleWithSAMLRequest();
                assumeRoleWithSAMLRequest.setPrincipalArn(principalArn);
                assumeRoleWithSAMLRequest.setRoleArn(roleArn);
                assumeRoleWithSAMLRequest.setSAMLAssertion(samlResponse);
                assumeRoleWithSAMLRequest.setDurationSeconds((long) currentDuration);
                String randSessionName = "tencentcloud-onelogin-" + Math.random();
                assumeRoleWithSAMLRequest.setRoleSessionName(randSessionName);
                AssumeRoleWithSAMLResponse assumeRoleWithSAMLResult = null;
                assumeRoleWithSAMLResult = stsClient.AssumeRoleWithSAML(assumeRoleWithSAMLRequest);

                Credentials stsCredentials = assumeRoleWithSAMLResult.getCredentials();

                if (profileName == null) {
                    String action = "export";
                    if (System.getProperty("os.name").toLowerCase().contains("win")) {
                        action = "set";
                    }
                    System.out.println("\n-----------------------------------------------------------------------\n");
                    System.out.println("Success!\n");
                    System.out.println("Assumed Role User: " + roleArn + "\n");
                    System.out.println("Temporary TencentCloud Credentials Granted via OneLogin\n ");
                    System.out.println("It will expire at " + assumeRoleWithSAMLResult.getExpiration());
                    System.out.println("Copy/Paste to set these as environment variables\n");
                    System.out.println("-----------------------------------------------------------------------\n");

                    System.out.println(action + " TENCENTCLOUD_TOKEN=" + stsCredentials.getToken());
                    System.out.println();
                    System.out.println(action + " TENCENTCLOUD_SECRET_ID=" + stsCredentials.getTmpSecretId());
                    System.out.println();
                    System.out.println(action + " TENCENTCLOUD_SECRET_KEY=" + stsCredentials.getTmpSecretKey());
                    System.out.println();
                } else {
                    String homeDir = System.getProperty("user.home") + "/.tccli";
                    Files.createDirectories(Paths.get(homeDir));

                    String cfgPath = homeDir + "/" + profileName + ".configure";
                    if (!Files.exists(Paths.get(cfgPath))) {
                        File cfgFile = new File(cfgPath);
                        cfgFile.createNewFile();
                        try (FileWriter writer = new FileWriter(cfgFile)) {
                            String defaultConfigure = "{\"_sys_param\": {\n" +
                                    "    \"arrayCount\": 10,\n" +
                                    "    \"output\": \"json\",\n" +
                                    "    \"region\": \"ap-guangzhou\",\n" +
                                    "    \"warning\": \"off\"\n" +
                                    "  }\n}";
                            writer.write(defaultConfigure);
                        }
                    }

                    String credPath = homeDir + "/" + profileName + ".credential";
                    if (!Files.exists(Paths.get(credPath))) {
                        File credFile = new File(credPath);
                        credFile.createNewFile();
                    }

                    File credFile = new File(credPath);
                    JsonObject configObject = new JsonObject();
                    configObject.addProperty("secretId", stsCredentials.getTmpSecretId());
                    configObject.addProperty("secretKey", stsCredentials.getTmpSecretKey());
                    configObject.addProperty("token", stsCredentials.getToken());


                    String credContent = new GsonBuilder().setPrettyPrinting().create().toJson(configObject);
                    try (FileWriter writer = new FileWriter(credFile)) {
                        writer.write(credContent);
                    }

                    System.out.println("\n-----------------------------------------------------------------------");
                    System.out.println("Success!\n");
                    System.out.println("Temporary TencentCloud Credentials Granted via OneLogin\n");
                    System.out.println("Updated TencentCloud profile '" + profileName + "' located at " + credFile.getAbsolutePath());
                    if (loop > (i + 1)) {
                        System.out.println("This process will regenerate credentials " + (loop - (i + 1)) + " more times.\n");
                        System.out.println("Press Ctrl + C to exit");
                    }
                }
            }
        } finally {
            scanner.close();
        }
    }

    public static Integer getSelection(Scanner scanner, int max) {
        Integer selection = Integer.valueOf(scanner.next());
        while (selection < 0 || selection >= max) {
            System.out.println("Wrong number, add a number between 0 - " + (max - 1));
            selection = Integer.valueOf(scanner.next());
        }
        return selection;
    }

    public static Map<String, Object> getSamlResponse(Client olClient, Scanner scanner, String oneloginUsernameOrEmail,
                                                      String oneloginPassword, String appId, String oneloginDomain, Map<String, String> mfaVerifyInfo, String ip)
            throws Exception {
        String otpToken, stateToken;
        Device deviceSelection;
        Long deviceId;
        String deviceIdStr = null;
        Map<String, Object> result = new HashMap<String, Object>();

        SAMLEndpointResponse samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword,
                appId, oneloginDomain, ip);
        String status = samlEndpointResponse.getType();

        // When the status is null, then the request failed.
        if (status == null) {
            System.out.println(samlEndpointResponse.getMessage());
            throw new Exception("SAML assertion failed");
        }

        while (status.equals("pending")) {
            TimeUnit.SECONDS.sleep(30);
            samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId,
                    oneloginDomain, ip);
            status = samlEndpointResponse.getType();
        }
        String samlResponse = null;
        if (status.equals("success")) {
            if (samlEndpointResponse.getMFA() != null) {
                MFA mfa = samlEndpointResponse.getMFA();
                stateToken = mfa.getStateToken();
                List<Device> devices = mfa.getDevices();

                if (mfaVerifyInfo == null) {
                    System.out.println();
                    System.out.println("MFA Required");
                    System.out.println("Authenticate using one of these devices:");
                } else {
                    deviceIdStr = mfaVerifyInfo.get("deviceId");
                    if (deviceIdStr == null || deviceIdStr.isEmpty()) {
                        System.out.println("No device info found");
                        mfaVerifyInfo = null;
                    } else if (!checkDeviceExists(devices, Long.parseLong(deviceIdStr))) {
                        System.out.println();
                        System.out.println("The device selected with ID " + deviceIdStr + " is not available anymore");
                        System.out.println("Those are the devices available now:");
                        mfaVerifyInfo = null;
                    }
                }

                if (mfaVerifyInfo == null) {
                    System.out.println("-----------------------------------------------------------------------");
                    Device device;
                    Integer deviceInput;
                    if (devices.size() == 1) {
                        deviceInput = 0;
                    } else {
                        for (int i = 0; i < devices.size(); i++) {
                            device = devices.get(i);
                            System.out.println(" " + i + " | " + device.getType());
                        }
                        System.out.println("-----------------------------------------------------------------------");
                        System.out.print("\nSelect the desired MFA Device [0-" + (devices.size() - 1) + "]: ");
                        deviceInput = getSelection(scanner, devices.size());
                    }

                    deviceSelection = devices.get(deviceInput);
                    deviceId = deviceSelection.getID();
                    deviceIdStr = deviceId.toString();

                    System.out.print("Enter the OTP Token for " + deviceSelection.getType() + ": ");
                    otpToken = scanner.next();
                    mfaVerifyInfo = new HashMap<String, String>();
                    mfaVerifyInfo.put("otpToken", otpToken);
                    mfaVerifyInfo.put("deviceId", deviceIdStr);
                } else {
                    otpToken = mfaVerifyInfo.get("otpToken");
                }
                result = verifyToken(olClient, scanner, appId,
                        deviceIdStr, stateToken, otpToken, mfaVerifyInfo);

            } else {
                samlResponse = samlEndpointResponse.getSAMLResponse();
                result.put("samlResponse", samlResponse);
                result.put("mfaVerifyInfo", mfaVerifyInfo);
            }
        }
        return result;
    }

    public static Integer getDuration(Scanner scanner) {
        Integer answer = null;
        String value = null;
        boolean start = true;
        while (answer == null || (answer < 900 || answer > 43200)) {
            if (!start) {
                System.out.println("Wrong value, insert a value between 900 and 43200: ");
            }
            start = false;
            value = scanner.next();
            try {
                answer = Integer.valueOf(value);
            } catch (Exception e) {
                continue;
            }
        }
        return answer;
    }

    public static Map<String, Object> getSamlResponse(Client olClient, Scanner scanner, String oneloginUsernameOrEmail,
                                                      String oneloginPassword, String appId, String oneloginDomain, Map<String, String> mfaVerifyInfo)
            throws Exception {
        return getSamlResponse(olClient, scanner, oneloginUsernameOrEmail, oneloginPassword, appId,
                oneloginDomain, mfaVerifyInfo, null);
    }

    public static Boolean checkDeviceExists(List<Device> devices, Long deviceId) {
        for (Device device : devices) {
            if (device.getID() == deviceId) {
                return true;
            }
        }
        return false;
    }

    public static Map<String, Object> verifyToken(Client olClient, Scanner scanner, String appId,
                                                  String deviceIdStr, String stateToken, String otpToken, Map<String, String> mfaVerifyInfo) {
        Map<String, Object> result = new HashMap<String, Object>();
        try {
            SAMLEndpointResponse samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId,
                    deviceIdStr, stateToken, otpToken, null);
            mfaVerifyInfo.put("otpToken", otpToken);
            String samlResponse = samlEndpointResponseAfterVerify.getSAMLResponse();
            result.put("samlResponse", samlResponse);
            result.put("mfaVerifyInfo", mfaVerifyInfo);
        } catch (Exception OAuthProblemException) {
            System.out.print("The OTP Token was invalid, please introduce a new one: ");
            otpToken = scanner.next();
            result = verifyToken(olClient, scanner, appId,
                    deviceIdStr, stateToken, otpToken, mfaVerifyInfo);
        }
        return result;
    }

}
