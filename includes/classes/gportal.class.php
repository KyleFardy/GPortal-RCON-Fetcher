<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
ob_start();

class GPORTAL_AUTH
{
    public $authData;
    public $cookieFile;
    private $accessToken;
    private $tokenExpiry;
    private $sessionEmailKey = 'user_email';
    private $sessionPasswordKey = 'user_password';
    private $sessionTokenKey = 'access_token';

    const GPORTAL_API_URL = "https://www.g-portal.com/ngpapi/";
    const GPORTAL_TOKEN_URL = "https://auth.g-portal.com/auth/realms/master/protocol/openid-connect/token";
    const GPORTAL_AUTH_URL = "https://auth.g-portal.com/auth/realms/master/protocol/openid-connect/auth";
    const GPORTAL_HOME_URL = "https://www.g-portal.com/en";
    const GPORTAL_EU_SERVERS_URL = "https://www.g-portal.com/eur/serviceIds";
    const GPORTAL_US_SERVERS_URL = "https://www.g-portal.com/int/serviceIds";
    const LOG_FILE = "gportal.log";

    public function __construct()
    {
        $tempDir = sys_get_temp_dir();
        $this->cookieFile = tempnam($tempDir, 'GPortalCookies_');

        if ($this->cookieFile === false) {
            throw new \RuntimeException("Failed To Create Temporary Cookie File In: $tempDir");
        }
    }

    public function log($message): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $formattedMessage = sprintf("[%s] %s%s", $timestamp, $message, PHP_EOL);

        try {
            file_put_contents(self::LOG_FILE, $formattedMessage, FILE_APPEND | LOCK_EX);
        } catch (\Throwable $e) {
            error_log("Log Write Failed: " . $e->getMessage());
        }
    }

    public function login(string $username, string $password)
    {
        $this->log("Logging Into G-Portal");

        try {
            $authUrl = self::GPORTAL_AUTH_URL . '?client_id=website&redirect_uri=' . urlencode(self::GPORTAL_HOME_URL) .
                '&response_mode=query&response_type=code&scope=' . urlencode('openid email profile gportal');

            $ch = curl_init($authUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_COOKIEJAR => $this->cookieFile,
                CURLOPT_COOKIEFILE => $this->cookieFile
            ]);

            $loginResponse = curl_exec($ch);

            if (curl_errno($ch)) {
                $error = curl_error($ch);
                $this->log("cURL Error While Fetching Login Page: $error");
                throw new Exception("Failed To Fetch Login Page: $error");
            }

            if (curl_getinfo($ch, CURLINFO_HTTP_CODE) !== 200) {
                $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $this->log("Failed To Fetch Login Page, Status Code: $status");
                $JSON = (object)[
                    'type' => 'error',
                    'title' => 'ERROR',
                    'message' => "Failed To Fetch Login Page, Status Code"
                ];
                return json_encode($JSON);
            }

            curl_close($ch);

            preg_match('/"loginAction"\s*:\s*"([^"]+)"/', $loginResponse, $matches);
            $loginActionUrl = $matches[1] ?? null;

            if (!$loginActionUrl) {
                $JSON = (object)[
                    'type' => 'error',
                    'title' => 'ERROR',
                    'message' => "Failed To Extract Login Url"
                ];
                throw new Exception("Failed To Extract The Login URL From The Login Page!");
            }

            $ch = curl_init($loginActionUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_COOKIEFILE => $this->cookieFile,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query([
                    'username' => $username,
                    'password' => $password,
                    'credentialId' => ''
                ]),
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/x-www-form-urlencoded'
                ],
                CURLOPT_HEADER => true,
                CURLOPT_FOLLOWLOCATION => false
            ]);

            $authResponse = curl_exec($ch);

            if (curl_errno($ch)) {
                $error = curl_error($ch);
                $this->log("cURL Error During Authentication: $error");
                $JSON = (object)[
                    'type' => 'error',
                    'title' => 'ERROR',
                    'message' => "Failed To Login, $error"
                ];
                return json_encode($JSON);
            }

            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $header = substr($authResponse, 0, $headerSize);
            $body = substr($authResponse, $headerSize);

            if ($httpCode === 302) {
                preg_match('/^location:\s*(.*?)(\r\n|\n|$)/mi', $header, $locationMatches);
                $locationHeader = trim($locationMatches[1] ?? '');

                if (!$locationHeader) {
                    $JSON = (object)[
                        'type' => 'error',
                        'title' => 'ERROR',
                        'message' => "Failed To Login, No Location Header Found"
                    ];
                    return json_encode($JSON);
                }

                parse_str(parse_url($locationHeader, PHP_URL_QUERY), $queryParams);
                $code = $queryParams['code'] ?? null;

                if (!$code) {
                    $JSON = (object)[
                        'type' => 'error',
                        'title' => 'ERROR',
                        'message' => "Failed To Extract Authentication Code"
                    ];
                    return json_encode($JSON);
                }

                $tokenUrl = self::GPORTAL_TOKEN_URL;
                $ch = curl_init($tokenUrl);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => http_build_query([
                        'grant_type' => 'authorization_code',
                        'code' => $code,
                        'redirect_uri' => self::GPORTAL_HOME_URL,
                        'client_id' => 'website'
                    ]),
                    CURLOPT_HTTPHEADER => [
                        'Content-Type: application/x-www-form-urlencoded'
                    ]
                ]);

                $tokenResponse = curl_exec($ch);

                if (curl_errno($ch)) {
                    $JSON = (object)[
                        'type' => 'error',
                        'title' => 'ERROR',
                        'message' => "Failed To Exchange Code For Access Token"
                    ];
                    return json_encode($JSON);
                }

                $tokenHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

                if ($tokenHttpCode !== 200) {
                    $JSON = (object)[
                        'type' => 'error',
                        'title' => 'ERROR',
                        'message' => "Failed To Login, Access Token, Status Code: $tokenHttpCode"
                    ];
                    return json_encode($JSON);
                }

                $tokenData = json_decode($tokenResponse, true);

                if (!isset($tokenData['access_token'])) {
                    $JSON = (object)[
                        'type' => 'error',
                        'title' => 'ERROR',
                        'message' => "Failed To Login, Access Token Not Found"
                    ];
                    return json_encode($JSON);
                }

                $this->accessToken = $tokenData['access_token'];
                $this->tokenExpiry = time() + ($tokenData['expires_in'] ?? 3600);

                $_SESSION[$this->sessionEmailKey] = base64_encode(htmlspecialchars($username));
                $_SESSION[$this->sessionPasswordKey] = base64_encode(htmlspecialchars($password));
                $_SESSION[$this->sessionTokenKey] = $this->accessToken;
                $_SESSION['token_expiry'] = $this->tokenExpiry;

                $this->log("Successfully Authenticated Via Access Token!");

                curl_close($ch);
                return $this->jsonResponse("SUCCESS", "You Have Successfully Logged In!", "success");
            } elseif ($httpCode !== 200) {
                $this->log("Authentication Failed, HTTP Status Code: $httpCode");
                return $this->jsonResponse("ERROR", "Failed To Login, Status Code: $httpCode", "error");
            } else {
                $this->log("Authentication Failed, HTTP Status Code: $httpCode");
                return $this->jsonResponse("ERROR", "Failed To Login, Invalid Email/Password", "error");
            }
        } catch (Exception $e) {
            $this->log("Failed To Login: " . $e->getMessage());
            return $this->jsonResponse("ERROR", "Failed To Login, Error: " . $e->getMessage(), "error");
        }
    }

    public function fetchServers(): array
    {
        if (!$this->isTokenValid()) {
            throw new Exception("Access Token Is Not Valid!");
        }

        $this->log("Fetching Servers From G-Portal (EU And US)");

        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $servers = [];

        try {
            $curlHandles = $this->initializeCurlHandles($multiHandle);

            $this->executeMultiCurl($multiHandle);

            $servers = $this->processMultiCurlResponses($multiHandle, $curlHandles);
        } catch (Exception $e) {
            foreach ($curlHandles as $ch) {
                if ($ch instanceof \CurlHandle) {
                    curl_multi_remove_handle($multiHandle, $ch);
                    curl_close($ch);
                }
            }
            curl_multi_close($multiHandle);
            $this->log("Error: " . $e->getMessage());
            throw $e;
        } finally {
            if (is_resource($multiHandle)) {
                curl_multi_close($multiHandle);
            }
        }

        return $servers;
    }

    private function initializeCurlHandles($multiHandle): array
    {
        $curlHandles = [];

        foreach (
            [
                'EU' => self::GPORTAL_EU_SERVERS_URL,
                'US' => self::GPORTAL_US_SERVERS_URL
            ] as $region => $url
        ) {
            $this->log("Initializing Request For $region Servers");

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0,
                CURLOPT_TIMEOUT => 2,
                CURLOPT_HTTPHEADER => [
                    'Authorization: Bearer ' . $_SESSION[$this->sessionTokenKey],
                    'Content-Type: application/json'
                ]
            ]);

            curl_multi_add_handle($multiHandle, $ch);
            $curlHandles[$region] = $ch;
        }

        return $curlHandles;
    }

    private function executeMultiCurl($multiHandle): void
    {
        $running = null;
        do {
            $status = curl_multi_exec($multiHandle, $running);
            if ($status > CURLM_OK) {
                throw new Exception("MultiCurl Error: " . curl_multi_strerror($status));
            }
            curl_multi_select($multiHandle);
        } while ($running > 0);
    }

    private function processMultiCurlResponses($multiHandle, array $curlHandles): array
    {
        $servers = [];

        foreach ($curlHandles as $region => $ch) {
            $this->log("Processing Response From $region");

            $response = curl_multi_getcontent($ch);
            $error = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if (!empty($error)) {
                throw new Exception("Curl Error From $region: $error");
            }

            if ($httpCode !== 200) {
                throw new Exception("Unexpected HTTP Code From $region: $httpCode");
            }

            $regionServers = json_decode($response, true);
            if (!is_array($regionServers)) {
                throw new Exception("Invalid JSON Format From $region Servers");
            }

            foreach ($regionServers as &$server) {
                $server['region'] = $region;
            }

            $servers = array_merge($servers, $regionServers);

            curl_multi_remove_handle($multiHandle, $ch);
            curl_close($ch);
        }

        return $servers;
    }

    public function fetchStatus($sid, $region)
    {
        if (!$this->isTokenValid()) {
            $this->refreshToken();
        }
        $this->log("[" . $sid . "] [" . $region . "]");
        $token = $this->getAccessToken();
        $url = self::GPORTAL_API_URL;
        $data = [
            "operationName" => "ctx",
            "variables" => [
                'sid' => $sid,
                'region' => $region,
            ],
            "query" => "query ctx(\$sid: Int!, \$region: REGION!) {\n  cfgContext(rsid: {id: \$sid, region: \$region}) {\n    ns {\n      ...CtxFields\n      __typename\n    }\n    errors {\n      mutator\n      affectedPaths\n      error {\n        class_\n        args\n        __typename\n      }\n      scope\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment GameServerFields on GameServer {\n  id\n  serverName\n  serverPort\n  serverIp\n  autoUpdate\n  __typename\n}\n\nfragment PermissionFields on Permission {\n  userName\n  created\n  __typename\n}\n\nfragment MysqlDbFields on CustomerMysqlDb {\n  httpUrl\n  host\n  port\n  database\n  username\n  password\n  __typename\n}\n\nfragment ServiceStateFields on ServiceState {\n  state\n  fsmState\n  fsmIsTransitioning\n  fsmIsExclusiveLocked\n  fsmFileAccess\n  fsmLastStateChange\n  fsmStateLiveProgress {\n    ... on InstallProgress {\n      action\n      percentage\n      __typename\n    }\n    ... on BroadcastProgress {\n      nextMessageAt\n      stateExitAt\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment RestartTaskFields on RestartTask {\n  id\n  runOnWeekday\n  runOnDayofmonth\n  runAtTimeofday\n  runInTimezone\n  schedule\n  data {\n    description\n    args\n    scheduleExtended\n    nextFireTime\n    __typename\n  }\n  __typename\n}\n\nfragment DisplayPortFields on DisplayPorts {\n  rconPort\n  queryPort\n  __typename\n}\n\nfragment SteamWorkshopItemFields on SteamWorkshopItem {\n  id\n  appId\n  itemType\n  name\n  links {\n    websiteUrl\n    __typename\n  }\n  summary\n  logo {\n    url\n    __typename\n  }\n  maps {\n    workshopId\n    mapName\n    __typename\n  }\n  dateCreated\n  dateModified\n  lastUpdateTime\n  __typename\n}\n\nfragment SevenDaysModFields on SevenDaysMod {\n  id\n  name\n  repoKey\n  active\n  created\n  modified\n  __typename\n}\n\nfragment MapParams on FarmingSimulatorMapParamsObject {\n  serverIp\n  webServerPort\n  webStatsCode\n  token\n  __typename\n}\n\nfragment TxAdminFields on TxAdmin {\n  enabled\n  port\n  username\n  password\n  __typename\n}\n\nfragment CtxFields on RootNamespace {\n  sys {\n    game {\n      name\n      key\n      platform\n      forumBoardId\n      supportedPlatforms\n      __typename\n    }\n    extraGameTranslationKeys\n    gameServer {\n      ...GameServerFields\n      __typename\n    }\n    permissionsOwner {\n      ...PermissionFields\n      __typename\n    }\n    permissions {\n      ...PermissionFields\n      __typename\n    }\n    mysqlDb {\n      ...MysqlDbFields\n      __typename\n    }\n    __typename\n  }\n  service {\n    config {\n      rsid {\n        id\n        region\n        __typename\n      }\n      type\n      hwId\n      state\n      ftpUser\n      ftpPort\n      ftpPassword\n      ftpReadOnly\n      ipAddress\n      rconPort\n      queryPort\n      autoBackup\n      dnsNames\n      currentVersion\n      targetVersion\n      __typename\n    }\n    latestRev {\n      id\n      created\n      __typename\n    }\n    maxSlots\n    files\n    memory {\n      base\n      effective\n      __typename\n    }\n    currentState {\n      ...ServiceStateFields\n      __typename\n    }\n    backups {\n      id\n      userSize\n      created\n      isAutoBackup\n      __typename\n    }\n    restartSchedule {\n      ...RestartTaskFields\n      __typename\n    }\n    dnsAvailableTlds\n    __typename\n  }\n  admin {\n    hardwareGuacamoleConnection {\n      url\n      __typename\n    }\n    __typename\n  }\n  profile {\n    __typename\n    ... on ProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      __typename\n    }\n    ... on MinecraftProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        additionalPorts\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      worlds\n      addonRam\n      isRamServer\n      ramOrderCreationDate\n      ramStopTimeUtc\n      isConnectedToBungeecord\n      bungeecordServerUrl\n      executables {\n        id\n        name\n        key\n        default\n        __typename\n      }\n      mods {\n        id\n        repoKey\n        name\n        image\n        mindRam\n        projectUrl\n        revisions {\n          id\n          created\n          executableId\n          extraData\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on CsgoProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        gotvPort\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      selectedWorkshopItems {\n        ...SteamWorkshopItemFields\n        __typename\n      }\n      installedMaps {\n        name\n        displayName\n        workshopItem {\n          ...SteamWorkshopItemFields\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on ValheimProfileNamespace {\n      name\n      cfgFiles\n      clientLink\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      enableDeleteSavegames\n      __typename\n    }\n    ... on HellLetLooseProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        statsPort\n        beaconPort\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      __typename\n    }\n    ... on AloftProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      serverRoomCode\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      enableDeleteSavegames\n      __typename\n    }\n    ... on SevenDaysToDieProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        telnetPort\n        webDashboardPort\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      availableMods {\n        ...SevenDaysModFields\n        __typename\n      }\n      isModUpdateAvailable\n      __typename\n    }\n    ... on SoulmaskProfileNamespace {\n      name\n      cfgFiles\n      gameUid\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      selectedWorkshopItems {\n        ...SteamWorkshopItemFields\n        __typename\n      }\n      __typename\n    }\n    ... on VRisingProfileNamespace {\n      name\n      cfgFiles\n      isLaunchServer\n      isOfficialServer\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      enableDeleteSavegames\n      __typename\n    }\n    ... on RustConsoleProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      modifyActionHints\n      __typename\n    }\n    ... on FarmingSimulatorProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      wiLink\n      defaultModSpace\n      masterWiLink\n      displayPorts {\n        rconPort\n        queryPort\n        webPort\n        __typename\n      }\n      mapParams {\n        ...MapParams\n        __typename\n      }\n      __typename\n    }\n    ... on BungeecordProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        additionalPorts\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      gpServers\n      accessibleMinecraftServers {\n        ...GameServerFields\n        __typename\n      }\n      __typename\n    }\n    ... on ConanProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      enableDeleteSavegames\n      selectedWorkshopItems {\n        ...SteamWorkshopItemFields\n        __typename\n      }\n      isModUpdateAvailable\n      __typename\n    }\n    ... on FiveMProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        __typename\n      }\n      enableCustomerDb\n      enableCustomHostnames\n      txAdmin {\n        ...TxAdminFields\n        __typename\n      }\n      __typename\n    }\n    ... on ScumProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      enableDeleteSavegames\n      displayPorts {\n        rconPort\n        queryPort\n        serverPort\n        __typename\n      }\n      __typename\n    }\n    ... on PalworldProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        rconPort\n        queryPort\n        __typename\n      }\n      enableDeleteSavegames\n      __typename\n    }\n    ... on AbioticFactorProfileNamespace {\n      name\n      cfgFiles\n      logFiles\n      publicConfigs\n      configDefinition\n      displayPorts {\n        ...DisplayPortFields\n        __typename\n      }\n      joinCode\n      __typename\n    }\n  }\n  __typename\n}"
        ];
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json',
            ],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
        ];
        $ch = curl_init();
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);
        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            return "cURL Error: $error";
        }
        curl_close($ch);
        $responseData = json_decode($response, true);
        if (isset($responseData['errors'])) {
            return $responseData['errors'][0]['message'];
        }
        return $responseData;
    }

    public function getUser($region)
    {
        if (!$this->isTokenValid()) {
            $this->refreshToken();
        }
        $token = $this->getAccessToken();
        $url = self::GPORTAL_API_URL;
        $data = [
            "operationName" => "me",
            "variables" => [
                'region' => $region,
            ],
            "query" => "query me(\$region: REGION!) {\n  me(region: \$region) {\n    jwt {\n      id\n      email\n      username\n      hasAllServiceAccess\n      __typename\n    }\n    __typename\n  }\n}"
        ];
        $options = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json',
            ],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
        ];
        $ch = curl_init();
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);
        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            return "cURL Error: $error";
        }
        curl_close($ch);
        $responseData = json_decode($response, true);
        if (isset($responseData['errors'])) {
            return $responseData['errors'][0]['message'];
        }
        return $responseData['data']['me']['jwt'];
    }

    public function isTokenValid(): bool
    {
        if (isset($_SESSION[$this->sessionTokenKey])) {
            $this->accessToken = $_SESSION[$this->sessionTokenKey];
            $this->tokenExpiry = $_SESSION['token_expiry'] ?? 0;

            $isValid = $this->tokenExpiry > time();
            $this->log("Token Validity Check: " . ($isValid ? "Valid" : "Expired"));
            return $isValid;
        }

        $this->log("Token Validity Check: No Token Found In Session");
        return false;
    }

    public function formatHostname($hostname)
    {
        $hostname = htmlspecialchars_decode($hostname);
        $hostname = preg_replace_callback('/<color=([^>]+)>(.*?)<\/color>/', function ($matches) {
            $color = $matches[1];
            return '<span style="color:' . $color . ';">' . $matches[2] . '</span>';
        }, $hostname);
        $hostname = preg_replace_callback('/<#[0-9A-Fa-f]{6}>(.)/', function ($matches) {
            $color = substr($matches[0], 1, 7);
            $char = $matches[1];
            return '<span style="color:' . $color . ';">' . $char . '</span>';
        }, $hostname);
        $hostname = preg_replace('/<b>(.*?)<\/b>/', '<strong>$1</strong>', $hostname);
        $hostname = preg_replace('/<i>(.*?)<\/i>/', '<em>$1</em>', $hostname);
        $hostname = preg_replace('/<u>(.*?)<\/u>/', '<u>$1</u>', $hostname);
        return $hostname;
    }

    public function refreshToken()
    {
        $refreshToken = $_SESSION['refresh_token'] ?? null;
        if (empty($refreshToken)) {
            $this->log("Missing Refresh Token In Session");
            throw new Exception("Missing Refresh Token");
        }

        $this->log("Refreshing The Authentication Token");

        $ch = curl_init(self::GPORTAL_TOKEN_URL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => 'website',
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
        ]);

        $tokenResponse = curl_exec($ch);

        if (curl_errno($ch)) {
            $error = curl_error($ch);
            $this->log("Failed To Refresh Token: $error");
            throw new Exception("Failed To Refresh Token: $error");
        }

        $tokenHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($tokenHttpCode !== 200) {
            $this->log("Failed To Refresh Token, HTTP Status Code: $tokenHttpCode");
            $this->log("Token Refresh Response Body: $tokenResponse");
            throw new Exception("Failed To Refresh Token, HTTP Status Code: $tokenHttpCode");
        }

        $tokenData = json_decode($tokenResponse, true);

        if (!isset($tokenData['access_token'])) {
            $this->log("Access Token Missing From Token Refresh Response");
            throw new Exception("Access Token Not Found In The Response!");
        }

        $this->accessToken = $tokenData['access_token'];
        $expiresIn = $tokenData['expires_in'] ?? 3600;
        $this->tokenExpiry = time() + $expiresIn;

        $_SESSION[$this->sessionTokenKey] = $this->accessToken;
        $_SESSION['token_expiry'] = $this->tokenExpiry;

        if (isset($tokenData['refresh_token'])) {
            $_SESSION['refresh_token'] = $tokenData['refresh_token'];
            $this->log("Refresh Token Also Updated In Session");
        }

        $this->log("Successfully Refreshed Token, New Access Token Stored");
        curl_close($ch);
    }

    public function getAccessToken()
    {
        $token = $_SESSION[$this->sessionTokenKey] ?? null;
        $this->log($token ? "Access Token Retrieved Successfully" : "Access Token Not Found In Session");
        return $token;
    }

    public function checkLoginStatus()
    {
        $status = $this->isTokenValid();
        $this->log("Login Status Check: " . ($status ? "Authenticated" : "Not Authenticated"));
        return $status;
    }

    public function redirect($page)
    {
        if (!headers_sent()) {
            header('Location: ' . $page);
            exit;
        } else {
            echo "<script>window.location.href = '" . addslashes($page) . "';</script>";
            echo "<noscript><meta http-equiv='refresh' content='0;url=" . htmlspecialchars($page, ENT_QUOTES) . "'></noscript>";
            exit;
        }
    }

    public function getServers()
    {
        if (!$this->checkLoginStatus()) {
            if (!$this->login(base64_decode($_SESSION[$this->sessionEmailKey]), base64_decode($_SESSION[$this->sessionPasswordKey]))) {
                throw new Exception("Login Failed");
            }
        } elseif (!$this->isTokenValid()) {
            if (!$this->refreshToken()) {
                throw new Exception("Token Refresh Failed");
            }
        }
        $JSON = new StdClass;
        foreach ($this->fetchServers() as $server) {
            $status = $this->fetchStatus($server['serviceId'], $server['region']);
            $hostname = 'Unknown';
            $rconPassword = 'N/A';
            $rconIpAddress = 'N/A';
            $rconPort = 'N/A';
            if (
                isset($status['data']['cfgContext']['ns']['profile']['publicConfigs']) &&
                is_string($status['data']['cfgContext']['ns']['profile']['publicConfigs'])
            ) {
                $profile = json_decode($status['data']['cfgContext']['ns']['profile']['publicConfigs'], true);
                $service = $status['data']['cfgContext']['ns']['service']['config'];
                if (isset($profile['server']['server.hostname'])) {
                    $hostname = $this->formatHostname($profile['server']['server.hostname']);
                }
                if (isset($profile['virtual']['rcon_password'])) {
                    $rconPassword = $profile['virtual']['rcon_password'];
                }
                if (isset($service['ipAddress'])) {
                    $rconIpAddress = $service['ipAddress'];
                }
                if (isset($service['rconPort'])) {
                    $rconPort = $service['rconPort'];
                }
            }
            $JSON->data[] = array(
                "hostname" => $hostname,
                "region" => $server['region'],
                "serverId" => $server['serverId'],
                "serviceId" => $server['serviceId'],
                "rconIpAddress" => $rconIpAddress,
                "rconPort" => $rconPort,
                "rconPassword" =>  $rconPassword
            );
        }
        return json_encode($JSON);
    }

    public function jsonResponse($title, $message, $type, $additionalData = [])
    {
        $data = new stdClass();
        $data->title = $title;
        $data->message = $message;
        $data->type = $type;
        if (!empty($additionalData)) {
            foreach ($additionalData as $key => $value) {
                $data->$key = $value;
            }
        }
        return json_encode($data);
    }

    public function verifyCsrfToken($token)
    {
        return (!empty($token) && !empty($_SESSION['csrfToken']) && hash_equals($_SESSION['csrfToken'], $token));
    }

    public function generateCsrfToken()
    {
        if (empty($_SESSION['csrfToken'])) {
            $_SESSION['csrfToken'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrfToken'];
    }
}
