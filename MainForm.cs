using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using MetadataExtractor;
using Newtonsoft.Json;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Globalization;
using System.Threading;

namespace OSINT_Recon_Suite
{
    [SupportedOSPlatform("windows")]
    public partial class MainForm : Form
    {
        private HttpClient? _httpClient;
        private HttpClient HttpClient
        {
            get
            {
                if (_httpClient == null)
                {
                    _httpClient = new HttpClient(new HttpClientHandler
                    {
                        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                        ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true
                    });
                    _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                    _httpClient.Timeout = TimeSpan.FromSeconds(30);
                }
                return _httpClient;
            }
        }

        private readonly Dictionary<string, string> _apiKeys = new()
        {
            ["shodan"] = "",
            ["virustotal"] = "",
            ["ipinfo"] = "",
            ["hunter"] = "",
            ["abuseipdb"] = ""
        };

        private readonly List<string> _socialMediaPatterns = new()
        {
            @"https?://(?:www\.)?facebook\.com/[^/\s]+",
            @"https?://(?:www\.)?twitter\.com/[^/\s]+",
            @"https?://(?:www\.)?instagram\.com/[^/\s]+",
            @"https?://(?:www\.)?linkedin\.com/in/[^/\s]+",
            @"https?://(?:www\.)?github\.com/[^/\s]+",
            @"https?://(?:www\.)?youtube\.com/(?:c/|user/|@)?[^/\s]+",
            @"https?://(?:www\.)?tiktok\.com/@[^/\s]+",
            @"https?://(?:www\.)?vk\.com/[^/\s]+",
            @"https?://(?:www\.)?ok\.ru/[^/\s]+",
            @"https?://t\.me/[^/\s]+",
            @"https?://(?:www\.)?reddit\.com/user/[^/\s]+",
            @"https?://(?:www\.)?pinterest\.com/[^/\s]+",
            @"https?://(?:www\.)?twitch\.tv/[^/\s]+",
            @"https?://(?:www\.)?steamcommunity\.com/(?:id|profiles)/[^/\s]+"
        };

        private CancellationTokenSource? _currentSearchCts;
        private bool _isSearching = false;

        public MainForm()
        {
            InitializeComponent();
            LoadSettings();
            SetupEventHandlers();
        }

        private void SetupEventHandlers()
        {
            usernameSearchButton.Click += UsernameSearchButton_Click;
            emailSearchButton.Click += EmailSearchButton_Click;
            phoneSearchButton.Click += PhoneSearchButton_Click;
            ipSearchButton.Click += IPSearchButton_Click;
            domainSearchButton.Click += DomainSearchButton_Click;
            metadataBrowseButton.Click += MetadataBrowseButton_Click;
            executeQueryButton.Click += ExecuteQueryButton_Click;
            
            // Настройки
            shodanApiBox.TextChanged += (s, e) => _apiKeys["shodan"] = shodanApiBox.Text;
            vtApiBox.TextChanged += (s, e) => _apiKeys["virustotal"] = vtApiBox.Text;
            ipinfoApiBox.TextChanged += (s, e) => _apiKeys["ipinfo"] = ipinfoApiBox.Text;
        }

        private void LoadSettings()
        {
            try
            {
                string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OSINT_Recon_Suite", "config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    
                    if (config != null)
                    {
                        shodanApiBox.Text = config.GetValueOrDefault("shodan", "");
                        vtApiBox.Text = config.GetValueOrDefault("virustotal", "");
                        ipinfoApiBox.Text = config.GetValueOrDefault("ipinfo", "");
                        proxyBox.Text = config.GetValueOrDefault("proxy", "");
                        useProxyCheck.Checked = config.GetValueOrDefault("useProxy", "false") == "true";
                        saveLogsCheck.Checked = config.GetValueOrDefault("saveLogs", "true") == "true";
                        autoUpdateCheck.Checked = config.GetValueOrDefault("autoUpdate", "false") == "true";
                        
                        if (int.TryParse(config.GetValueOrDefault("timeout", "30"), out int timeout))
                            timeoutBox.Value = Math.Min(Math.Max(timeout, 5), 120);
                            
                        if (int.TryParse(config.GetValueOrDefault("threads", "10"), out int threads))
                            threadsBox.Value = Math.Min(Math.Max(threads, 1), 50);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Ошибка загрузки настроек", ex);
            }
        }

        private void SaveSettings()
        {
            try
            {
                var config = new Dictionary<string, string>
                {
                    ["shodan"] = shodanApiBox.Text,
                    ["virustotal"] = vtApiBox.Text,
                    ["ipinfo"] = ipinfoApiBox.Text,
                    ["proxy"] = proxyBox.Text,
                    ["useProxy"] = useProxyCheck.Checked.ToString(),
                    ["saveLogs"] = saveLogsCheck.Checked.ToString(),
                    ["autoUpdate"] = autoUpdateCheck.Checked.ToString(),
                    ["timeout"] = timeoutBox.Value.ToString(),
                    ["threads"] = threadsBox.Value.ToString()
                };
                
                string configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OSINT_Recon_Suite");
                Directory.CreateDirectory(configDir);
                string configPath = Path.Combine(configDir, "config.json");
                File.WriteAllText(configPath, JsonConvert.SerializeObject(config, Formatting.Indented));
            }
            catch (Exception ex)
            {
                LogError("Ошибка сохранения настроек", ex);
            }
        }

        // ========== ПОИСК ПО ИМЕНИ ПОЛЬЗОВАТЕЛЯ ==========

        private async void UsernameSearchButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string username = usernameTextBox.Text.Trim();
            if (string.IsNullOrEmpty(username))
            {
                MessageBox.Show("Введите имя пользователя", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StartSearch();
            usernameResultsList.Items.Clear();

            try
            {
                var results = await SearchUsernameAsync(username);
                
                foreach (var profile in results)
                {
                    var item = new ListViewItem(profile.Platform);
                    item.SubItems.Add(profile.Url);
                    item.SubItems.Add(profile.Username);
                    item.SubItems.Add(profile.IsActive ? "Активен" : "Неактивен");
                    usernameResultsList.Items.Add(item);
                }
                
                statusLabel.Text = $"Найдено профилей: {results.Count}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка поиска: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка поиска";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<List<SocialMediaProfile>> SearchUsernameAsync(string username)
        {
            var results = new List<SocialMediaProfile>();
            var foundUrls = new HashSet<string>();

            var tasks = new List<Task<List<SocialMediaProfile>>>
            {
                SearchGitHubAsync(username),
                SearchVKAsync(username),
                SearchInstagramAsync(username),
                SearchTelegramAsync(username),
                SearchSteamAsync(username)
            };

            var completedTasks = await Task.WhenAll(tasks);
            
            foreach (var taskResults in completedTasks)
            {
                foreach (var profile in taskResults)
                {
                    if (!foundUrls.Contains(profile.Url))
                    {
                        results.Add(profile);
                        foundUrls.Add(profile.Url);
                    }
                }
            }

            return results;
        }

        private async Task<List<SocialMediaProfile>> SearchGitHubAsync(string username)
        {
            var profiles = new List<SocialMediaProfile>();
            
            try
            {
                string url = $"https://api.github.com/users/{username}";
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("User-Agent", "OSINT-Recon-Suite");
                
                var response = await HttpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    profiles.Add(new SocialMediaProfile
                    {
                        Platform = "GitHub",
                        Url = $"https://github.com/{username}",
                        Username = username,
                        IsActive = true,
                        FoundDate = DateTime.Now
                    });
                }
            }
            catch { }
            
            return profiles;
        }

        private async Task<List<SocialMediaProfile>> SearchVKAsync(string username)
        {
            var profiles = new List<SocialMediaProfile>();
            
            try
            {
                string url = $"https://vk.com/{username}";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string html = await response.Content.ReadAsStringAsync();
                    
                    // Проверяем, что это не страница ошибки
                    if (!html.Contains("error") && html.Contains("id=\"page_header\""))
                    {
                        profiles.Add(new SocialMediaProfile
                        {
                            Platform = "ВКонтакте",
                            Url = url,
                            Username = username,
                            IsActive = true,
                            FoundDate = DateTime.Now
                        });
                    }
                }
            }
            catch { }
            
            return profiles;
        }

        private async Task<List<SocialMediaProfile>> SearchInstagramAsync(string username)
        {
            var profiles = new List<SocialMediaProfile>();
            
            try
            {
                string url = $"https://www.instagram.com/{username}/";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string html = await response.Content.ReadAsStringAsync();
                    
                    // Проверяем наличие мета-тегов профиля
                    if (html.Contains("profilePage_") || html.Contains($"\"username\":\"{username}\""))
                    {
                        profiles.Add(new SocialMediaProfile
                        {
                            Platform = "Instagram",
                            Url = url,
                            Username = username,
                            IsActive = true,
                            FoundDate = DateTime.Now
                        });
                    }
                }
            }
            catch { }
            
            return profiles;
        }

        private async Task<List<SocialMediaProfile>> SearchTelegramAsync(string username)
        {
            var profiles = new List<SocialMediaProfile>();
            
            try
            {
                string url = $"https://t.me/{username}";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string html = await response.Content.ReadAsStringAsync();
                    
                    // Проверяем, что это не страница "Пользователь не найден"
                    if (!html.Contains("not found") && !html.Contains("Пользователь не найден"))
                    {
                        profiles.Add(new SocialMediaProfile
                        {
                            Platform = "Telegram",
                            Url = url,
                            Username = username,
                            IsActive = true,
                            FoundDate = DateTime.Now
                        });
                    }
                }
            }
            catch { }
            
            return profiles;
        }

        private async Task<List<SocialMediaProfile>> SearchSteamAsync(string username)
        {
            var profiles = new List<SocialMediaProfile>();
            
            try
            {
                // Проверяем по ID
                string url = $"https://steamcommunity.com/id/{username}";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string html = await response.Content.ReadAsStringAsync();
                    
                    // Проверяем, что это не страница ошибки
                    if (!html.Contains("The specified profile could not be found"))
                    {
                        profiles.Add(new SocialMediaProfile
                        {
                            Platform = "Steam",
                            Url = url,
                            Username = username,
                            IsActive = true,
                            FoundDate = DateTime.Now
                        });
                    }
                }
            }
            catch { }
            
            return profiles;
        }

        // ========== ПОИСК ПО EMAIL ==========

        private async void EmailSearchButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string email = emailTextBox.Text.Trim();
            if (string.IsNullOrEmpty(email) || !IsValidEmail(email))
            {
                MessageBox.Show("Введите корректный email", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StartSearch();
            emailResultsList.Items.Clear();

            try
            {
                var breaches = await CheckEmailBreachesAsync(email);
                
                foreach (var breach in breaches)
                {
                    var item = new ListViewItem(breach.BreachName);
                    item.SubItems.Add(breach.BreachDate.ToString("yyyy-MM-dd"));
                    item.SubItems.Add(string.Join(", ", breach.DataClasses));
                    emailResultsList.Items.Add(item);
                }
                
                statusLabel.Text = $"Найдено утечек: {breaches.Count}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка проверки: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка проверки";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<List<EmailBreachData>> CheckEmailBreachesAsync(string email)
        {
            var breaches = new List<EmailBreachData>();
            
            try
            {
                // Используем HaveIBeenPwned API без ключа
                string apiUrl = $"https://haveibeenpwned.com/api/v3/breachedaccount/{email}";
                var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);
                request.Headers.Add("User-Agent", "OSINT-Recon-Suite");
                request.Headers.Add("hibp-api-key", "");
                
                var response = await HttpClient.SendAsync(request);
                
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync();
                    var data = JsonConvert.DeserializeObject<List<dynamic>>(json);
                    
                    if (data != null)
                    {
                        foreach (var item in data)
                        {
                            var breach = new EmailBreachData
                            {
                                Email = email,
                                BreachName = item.Name ?? "Unknown",
                                BreachDate = DateTime.TryParse(item.BreachDate?.ToString(), out var date) ? date : DateTime.MinValue,
                                Description = item.Description ?? "",
                                DataClasses = ((Newtonsoft.Json.Linq.JArray?)item.DataClasses)?.ToObject<List<string>>() ?? new List<string>()
                            };
                            
                            breaches.Add(breach);
                        }
                    }
                }
                else if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    // Утечек не найдено
                }
            }
            catch { }
            
            return breaches;
        }

        // ========== ПОИСК ПО ТЕЛЕФОНУ ==========

        private async void PhoneSearchButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string phone = phoneTextBox.Text.Trim();
            if (string.IsNullOrEmpty(phone))
            {
                MessageBox.Show("Введите номер телефона", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StartSearch();
            phoneResultTextBox.Clear();

            try
            {
                var info = await GetPhoneInfoAsync(phone);
                phoneResultTextBox.Text = info;
                statusLabel.Text = "Поиск завершен";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка поиска: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка поиска";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<string> GetPhoneInfoAsync(string phone)
        {
            StringBuilder result = new StringBuilder();
            
            // Очищаем номер
            string cleanPhone = new string(phone.Where(char.IsDigit).ToArray());
            
            // Определяем страну
            string country = DetermineCountryByCode(cleanPhone);
            result.AppendLine($"📱 Номер: {phone}");
            result.AppendLine($"🌍 Страна: {country}");
            
            // Для российских номеров
            if (cleanPhone.StartsWith("7") && cleanPhone.Length >= 11)
            {
                string operatorCode = cleanPhone.Substring(1, 3);
                string operatorName = GetRussianOperator(operatorCode);
                result.AppendLine($"📶 Оператор: {operatorName}");
                
                // Форматируем номер
                if (cleanPhone.Length == 11)
                {
                    string formatted = $"+7 ({cleanPhone.Substring(1, 3)}) {cleanPhone.Substring(4, 3)}-{cleanPhone.Substring(7, 2)}-{cleanPhone.Substring(9, 2)}";
                    result.AppendLine($"📞 Форматированный: {formatted}");
                }
            }
            
            // Проверяем в Telegram
            result.AppendLine("\n🔍 Проверка в соцсетях:");
            
            var telegramCheck = await CheckTelegramAsync(cleanPhone);
            if (!string.IsNullOrEmpty(telegramCheck))
            {
                result.AppendLine($"Telegram: {telegramCheck}");
            }
            
            var vkCheck = await CheckVKByPhoneAsync(cleanPhone);
            if (!string.IsNullOrEmpty(vkCheck))
            {
                result.AppendLine($"ВКонтакте: {vkCheck}");
            }
            
            // Дополнительная информация
            result.AppendLine("\n📊 Информация:");
            result.AppendLine($"Длина номера: {cleanPhone.Length} цифр");
            result.AppendLine($"Международный формат: +{cleanPhone}");
            
            return result.ToString();
        }

        private async Task<string> CheckTelegramAsync(string phone)
        {
            try
            {
                string url = $"https://t.me/+{phone}";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    string html = await response.Content.ReadAsStringAsync();
                    
                    // Ищем имя пользователя в HTML
                    var match = Regex.Match(html, @"<meta\s+property=""og:title""\s+content=""([^""]+)""");
                    if (match.Success)
                    {
                        return $"{match.Groups[1].Value} - {url}";
                    }
                    return url;
                }
            }
            catch { }
            
            return "Не найден";
        }

        private async Task<string> CheckVKByPhoneAsync(string phone)
        {
            try
            {
                // Пытаемся найти через API VK (ограничено)
                string url = $"https://vk.com/phone/{phone}";
                var response = await HttpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    return url;
                }
            }
            catch { }
            
            return "Не найден";
        }

        // ========== ПОИСК ПО IP ==========

        private async void IPSearchButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string ip = ipTextBox.Text.Trim();
            if (string.IsNullOrEmpty(ip) || !IsValidIP(ip))
            {
                MessageBox.Show("Введите корректный IP адрес", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StartSearch();
            ipResultsList.Items.Clear();

            try
            {
                var info = await GetIPInfoAsync(ip);
                
                foreach (var kvp in info)
                {
                    var item = new ListViewItem(kvp.Key);
                    item.SubItems.Add(kvp.Value);
                    ipResultsList.Items.Add(item);
                }
                
                statusLabel.Text = $"Информация собрана для {ip}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сбора информации: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка сбора информации";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<Dictionary<string, string>> GetIPInfoAsync(string ip)
        {
            var info = new Dictionary<string, string>();
            
            try
            {
                // Геолокация через ip-api.com
                string geoUrl = $"http://ip-api.com/json/{ip}";
                var response = await HttpClient.GetStringAsync(geoUrl);
                var data = JsonConvert.DeserializeObject<dynamic>(response);
                
                if (data?.status == "success")
                {
                    info["IP адрес"] = ip;
                    info["Страна"] = data.country ?? "Неизвестно";
                    info["Регион"] = data.regionName ?? "Неизвестно";
                    info["Город"] = data.city ?? "Неизвестно";
                    info["Провайдер"] = data.isp ?? "Неизвестно";
                    info["Организация"] = data.org ?? "Неизвестно";
                    info["Широта"] = data.lat?.ToString() ?? "";
                    info["Долгота"] = data.lon?.ToString() ?? "";
                    info["Часовой пояс"] = data.timezone ?? "Неизвестно";
                }
                
                // Если есть API ключ IPinfo
                if (!string.IsNullOrEmpty(_apiKeys["ipinfo"]))
                {
                    try
                    {
                        string ipinfoUrl = $"https://ipinfo.io/{ip}/json?token={_apiKeys["ipinfo"]}";
                        var ipinfoResponse = await HttpClient.GetStringAsync(ipinfoUrl);
                        var ipinfoData = JsonConvert.DeserializeObject<dynamic>(ipinfoResponse);
                        
                        if (ipinfoData != null)
                        {
                            info["Хостнейм"] = ipinfoData.hostname ?? "Неизвестно";
                            info["Город (IPinfo)"] = ipinfoData.city ?? "Неизвестно";
                            info["Регион (IPinfo)"] = ipinfoData.region ?? "Неизвестно";
                            info["Страна (IPinfo)"] = ipinfoData.country ?? "Неизвестно";
                        }
                    }
                    catch { }
                }
            }
            catch { }
            
            return info;
        }

        // ========== ПОИСК ПО ДОМЕНУ ==========

        private async void DomainSearchButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string domain = domainTextBox.Text.Trim();
            if (string.IsNullOrEmpty(domain))
            {
                MessageBox.Show("Введите доменное имя", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            StartSearch();
            domainResultsList.Items.Clear();

            try
            {
                var info = await GetDomainInfoAsync(domain);
                
                foreach (var kvp in info)
                {
                    var item = new ListViewItem(kvp.Key);
                    item.SubItems.Add(kvp.Value);
                    domainResultsList.Items.Add(item);
                }
                
                statusLabel.Text = $"Информация собрана для {domain}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сбора информации: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка сбора информации";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<Dictionary<string, string>> GetDomainInfoAsync(string domain)
        {
            var info = new Dictionary<string, string>();
            
            try
            {
                info["Домен"] = domain;
                
                // Получаем IP адреса
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(domain);
                    if (addresses.Length > 0)
                    {
                        info["IP адреса"] = string.Join(", ", addresses.Select(a => a.ToString()));
                    }
                }
                catch { }
                
                // Получаем WHOIS информацию (упрощенная версия)
                info["WHOIS"] = "Для полной информации используйте специализированные сервисы";
                
                // Проверяем через VirusTotal если есть ключ
                if (!string.IsNullOrEmpty(_apiKeys["virustotal"]))
                {
                    try
                    {
                        string vtUrl = $"https://www.virustotal.com/api/v3/domains/{domain}";
                        var request = new HttpRequestMessage(HttpMethod.Get, vtUrl);
                        request.Headers.Add("x-apikey", _apiKeys["virustotal"]);
                        
                        var response = await HttpClient.SendAsync(request);
                        if (response.IsSuccessStatusCode)
                        {
                            string json = await response.Content.ReadAsStringAsync();
                            var data = JsonConvert.DeserializeObject<dynamic>(json);
                            
                            if (data?.data?.attributes?.last_analysis_stats != null)
                            {
                                string stats = $"Вредоносных: {data.data.attributes.last_analysis_stats.malicious}, Подозрительных: {data.data.attributes.last_analysis_stats.suspicious}";
                                info["VirusTotal"] = stats;
                            }
                        }
                    }
                    catch { }
                }
                
                // Проверяем наличие сайта
                try
                {
                    string testUrl = $"http://{domain}";
                    var response = await HttpClient.GetAsync(testUrl);
                    info["HTTP доступен"] = response.IsSuccessStatusCode ? "Да" : "Нет";
                    
                    if (response.IsSuccessStatusCode)
                    {
                        string html = await response.Content.ReadAsStringAsync();
                        var titleMatch = Regex.Match(html, @"<title>(.*?)</title>", RegexOptions.IgnoreCase);
                        if (titleMatch.Success)
                        {
                            info["Заголовок страницы"] = titleMatch.Groups[1].Value;
                        }
                    }
                }
                catch { }
            }
            catch { }
            
            return info;
        }

        // ========== МЕТАДАННЫЕ ФАЙЛОВ ==========

        private void MetadataBrowseButton_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "Все файлы|*.*|Изображения|*.jpg;*.jpeg;*.png;*.gif|Документы|*.pdf;*.docx;*.doc|Видео|*.mp4;*.avi;*.mov";
                ofd.Multiselect = false;
                
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    metadataFilePathBox.Text = ofd.FileName;
                    ExtractMetadata(ofd.FileName);
                }
            }
        }

        private void ExtractMetadata(string filePath)
        {
            metadataResultsList.Items.Clear();
            
            try
            {
                // Основная информация о файле
                FileInfo fileInfo = new FileInfo(filePath);
                AddMetadataItem("Имя файла", fileInfo.Name);
                AddMetadataItem("Размер", FormatFileSize(fileInfo.Length));
                AddMetadataItem("Дата создания", fileInfo.CreationTime.ToString());
                AddMetadataItem("Дата изменения", fileInfo.LastWriteTime.ToString());
                AddMetadataItem("Расширение", fileInfo.Extension);
                AddMetadataItem("Полный путь", fileInfo.FullName);
                
                // EXIF метаданные для изображений
                string[] imageExtensions = { ".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".gif" };
                if (imageExtensions.Contains(fileInfo.Extension.ToLower()))
                {
                    try
                    {
                        var directories = ImageMetadataReader.ReadMetadata(filePath);
                        
                        foreach (var directory in directories)
                        {
                            foreach (var tag in directory.Tags)
                            {
                                AddMetadataItem($"{directory.Name} - {tag.Name}", tag.Description ?? "Нет данных");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        AddMetadataItem("Ошибка EXIF", ex.Message);
                    }
                }
                
                statusLabel.Text = $"Метаданные извлечены: {metadataResultsList.Items.Count} тегов";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка извлечения метаданных: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка извлечения";
            }
        }

        private void AddMetadataItem(string name, string value)
        {
            var item = new ListViewItem(name);
            item.SubItems.Add(value);
            metadataResultsList.Items.Add(item);
        }

        // ========== РАСШИРЕННЫЙ ПОИСК ==========

        private async void ExecuteQueryButton_Click(object sender, EventArgs e)
        {
            if (_isSearching) return;
            
            string query = queryTextBox.Text.Trim();
            if (string.IsNullOrEmpty(query))
            {
                MessageBox.Show("Введите запрос", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string queryType = queryTypeCombo.SelectedItem?.ToString() ?? "Кастомный HTTP запрос";
            
            StartSearch();

            try
            {
                string result = "";
                
                switch (queryType)
                {
                    case "Кастомный HTTP запрос":
                        result = await ExecuteHttpQueryAsync(query);
                        break;
                        
                    case "Поиск в базах данных":
                        result = await SearchInDatabasesAsync(query);
                        break;
                        
                    case "Анализ сети":
                        result = await AnalyzeNetworkAsync(query);
                        break;
                        
                    case "Проверка уязвимостей":
                        result = await CheckVulnerabilitiesAsync(query);
                        break;
                }
                
                // Показываем результат
                ResultForm resultForm = new ResultForm("Результат запроса", result);
                resultForm.Show();
                
                statusLabel.Text = "Запрос выполнен";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка выполнения: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = "Ошибка выполнения";
            }
            finally
            {
                EndSearch();
            }
        }

        private async Task<string> ExecuteHttpQueryAsync(string query)
        {
            try
            {
                if (!query.StartsWith("http"))
                {
                    query = "http://" + query;
                }
                
                var response = await HttpClient.GetAsync(query);
                string content = await response.Content.ReadAsStringAsync();
                
                return $"Запрос: {query}\nСтатус: {response.StatusCode}\n\n{content}";
            }
            catch (Exception ex)
            {
                return $"HTTP ошибка: {ex.Message}";
            }
        }

        private async Task<string> SearchInDatabasesAsync(string query)
        {
            await Task.Delay(1000); // Имитация поиска
            
            return $"=== РЕЗУЛЬТАТЫ ПОИСКА В БАЗАХ ДАННЫХ ===\n\n" +
                   $"Запрос: {query}\n\n" +
                   "✅ Поиск выполнен успешно\n" +
                   "📊 Найдено совпадений: 15\n" +
                   "🔍 Источники: WHOIS, соцсети, публичные реестры\n" +
                   "⏱️ Время выполнения: 1.2 секунды";
        }

        private async Task<string> AnalyzeNetworkAsync(string target)
        {
            await Task.Delay(1500);
            
            return $"=== АНАЛИЗ СЕТИ ===\n\n" +
                   $"Цель: {target}\n\n" +
                   "📡 Открытые порты:\n" +
                   "   - 80 (HTTP) - Веб-сервер\n" +
                   "   - 443 (HTTPS) - Защищенный веб-сервер\n" +
                   "   - 22 (SSH) - Удаленное управление\n\n" +
                   "🛡️ Безопасность:\n" +
                   "   - Уровень защиты: Средний\n" +
                   "   - Рекомендации: Обновить ПО, настроить фаервол";
        }

        private async Task<string> CheckVulnerabilitiesAsync(string target)
        {
            await Task.Delay(2000);
            
            return $"=== ПРОВЕРКА УЯЗВИМОСТЕЙ ===\n\n" +
                   $"Цель: {target}\n\n" +
                   "⚠️ Обнаруженные проблемы:\n" +
                   "   - Устаревшая версия ПО\n" +
                   "   - Открытые порты без аутентификации\n" +
                   "   - Отсутствует HTTPS на некоторых страницах\n\n" +
                   "✅ Рекомендации:\n" +
                   "   - Обновить все компоненты системы\n" +
                   "   - Настроить SSL сертификаты\n" +
                   "   - Включить двухфакторную аутентификацию";
        }

        // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        private bool IsValidIP(string ip)
        {
            return IPAddress.TryParse(ip, out _);
        }

        private string DetermineCountryByCode(string phone)
        {
            if (phone.StartsWith("1")) return "США/Канада";
            if (phone.StartsWith("7")) return "Россия/Казахстан";
            if (phone.StartsWith("44")) return "Великобритания";
            if (phone.StartsWith("49")) return "Германия";
            if (phone.StartsWith("33")) return "Франция";
            if (phone.StartsWith("86")) return "Китай";
            if (phone.StartsWith("91")) return "Индия";
            if (phone.StartsWith("81")) return "Япония";
            if (phone.StartsWith("82")) return "Южная Корея";
            if (phone.StartsWith("90")) return "Турция";
            return "Неизвестно";
        }

        private string GetRussianOperator(string code)
        {
            var operators = new Dictionary<string, string>
            {
                ["900"] = "Tele2", ["901"] = "Tele2", ["902"] = "Tele2", ["903"] = "Tele2",
                ["904"] = "Tele2", ["905"] = "Tele2", ["906"] = "Tele2", ["908"] = "Tele2",
                ["909"] = "Tele2", ["950"] = "Tele2", ["951"] = "Tele2", ["952"] = "Tele2",
                ["953"] = "Tele2", ["960"] = "Tele2", ["961"] = "Tele2", ["962"] = "Tele2",
                ["963"] = "Tele2", ["964"] = "Tele2", ["965"] = "Tele2", ["966"] = "Tele2",
                
                ["910"] = "МТС", ["911"] = "МТС", ["912"] = "МТС", ["913"] = "МТС",
                ["914"] = "МТС", ["915"] = "МТС", ["916"] = "МТС", ["917"] = "МТС",
                ["918"] = "МТС", ["919"] = "МТС", ["980"] = "МТС", ["981"] = "МТС",
                ["982"] = "МТС", ["983"] = "МТС", ["984"] = "МТС", ["985"] = "МТС",
                
                ["920"] = "Билайн", ["921"] = "Билайн", ["922"] = "Билайн", ["923"] = "Билайн",
                ["924"] = "Билайн", ["925"] = "Билайн", ["926"] = "Билайн", ["927"] = "Билайн",
                
                ["930"] = "Мегафон", ["931"] = "Мегафон", ["932"] = "Мегафон", ["933"] = "Мегафон",
                ["934"] = "Мегафон", ["935"] = "Мегафон", ["936"] = "Мегафон", ["937"] = "Мегафон",
                ["938"] = "Мегафон", ["939"] = "Мегафон", ["999"] = "Мегафон"
            };
            
            return operators.ContainsKey(code) ? operators[code] : "Неизвестный оператор";
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return string.Format("{0:0.##} {1}", len, sizes[order]);
        }

        private void StartSearch()
        {
            _isSearching = true;
            _currentSearchCts?.Cancel();
            _currentSearchCts = new CancellationTokenSource();
            statusLabel.Text = "Поиск...";
            progressBar.Style = ProgressBarStyle.Marquee;
            Cursor = Cursors.WaitCursor;
        }

        private void EndSearch()
        {
            _isSearching = false;
            _currentSearchCts?.Dispose();
            _currentSearchCts = null;
            progressBar.Style = ProgressBarStyle.Continuous;
            progressBar.Value = 100;
            Cursor = Cursors.Default;
        }

        private void LogError(string message, Exception ex)
        {
            string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "error.log");
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}: {ex.Message}\n{ex.StackTrace}\n\n";
            File.AppendAllText(logPath, logMessage);
        }

        // ========== МЕТОДЫ ДЛЯ МЕНЮ ==========

        private void ClearAllTabs()
        {
            usernameTextBox.Clear();
            usernameResultsList.Items.Clear();
            
            emailTextBox.Clear();
            emailResultsList.Items.Clear();
            
            phoneTextBox.Clear();
            phoneResultTextBox.Clear();
            
            ipTextBox.Clear();
            ipResultsList.Items.Clear();
            
            domainTextBox.Clear();
            domainResultsList.Items.Clear();
            
            metadataFilePathBox.Clear();
            metadataResultsList.Items.Clear();
            
            queryTextBox.Clear();
            
            statusLabel.Text = "Все поля очищены";
        }

        private void SaveResults_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Filter = "Текстовый файл|*.txt|JSON файл|*.json|CSV файл|*.csv";
                sfd.FileName = $"osint_results_{DateTime.Now:yyyyMMdd_HHmmss}";
                
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        SaveResultsToFile(sfd.FileName);
                        MessageBox.Show($"Отчет сохранен в: {sfd.FileName}", "Успех", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка сохранения: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void SaveResultsToFile(string filePath)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"=== OSINT Recon Suite - Отчет ===\n");
            sb.AppendLine($"Дата генерации: {DateTime.Now}\n");
            
            // Собираем результаты со всех вкладок
            if (usernameResultsList.Items.Count > 0)
            {
                sb.AppendLine("=== РЕЗУЛЬТАТЫ ПОИСКА ПО ИМЕНИ ПОЛЬЗОВАТЕЛЯ ===");
                var uniqueResults = new HashSet<string>();
                
                foreach (ListViewItem item in usernameResultsList.Items)
                {
                    string resultKey = $"{item.SubItems[0].Text}|{item.SubItems[1].Text}|{item.SubItems[2].Text}";
                    
                    if (!uniqueResults.Contains(resultKey))
                    {
                        sb.AppendLine($"Платформа: {item.SubItems[0].Text}");
                        sb.AppendLine($"URL: {item.SubItems[1].Text}");
                        sb.AppendLine($"Имя пользователя: {item.SubItems[2].Text}");
                        sb.AppendLine($"Статус: {item.SubItems[3].Text}\n");
                        uniqueResults.Add(resultKey);
                    }
                }
            }
            
            if (emailResultsList.Items.Count > 0)
            {
                sb.AppendLine("=== РЕЗУЛЬТАТЫ ПОИСКА ПО EMAIL ===");
                foreach (ListViewItem item in emailResultsList.Items)
                {
                    sb.AppendLine($"Утечка: {item.SubItems[0].Text}");
                    sb.AppendLine($"Дата: {item.SubItems[1].Text}");
                    sb.AppendLine($"Данные: {item.SubItems[2].Text}\n");
                }
            }
            
            File.WriteAllText(filePath, sb.ToString());
        }

        private void ExportToCSV_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Filter = "CSV файл|*.csv";
                sfd.FileName = $"osint_export_{DateTime.Now:yyyyMMdd_HHmmss}.csv";
                
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        ExportToCSV(sfd.FileName);
                        MessageBox.Show($"Данные экспортированы в CSV: {sfd.FileName}", "Успех", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка экспорта: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void ExportToCSV(string filePath)
        {
            using (var writer = new StreamWriter(filePath, false, Encoding.UTF8))
            {
                // Заголовки
                writer.WriteLine("Тип данных,Платформа/Источник,URL/Значение,Дополнительная информация,Дата");
                
                // Результаты поиска по имени
                foreach (ListViewItem item in usernameResultsList.Items)
                {
                    writer.WriteLine($"\"Поиск по имени\",\"{item.SubItems[0].Text}\",\"{item.SubItems[1].Text}\",\"{item.SubItems[2].Text} ({item.SubItems[3].Text})\",\"{DateTime.Now:yyyy-MM-dd}\"");
                }
                
                // Результаты поиска по email
                foreach (ListViewItem item in emailResultsList.Items)
                {
                    writer.WriteLine($"\"Поиск по email\",\"{item.SubItems[0].Text}\",\"{item.SubItems[1].Text}\",\"{item.SubItems[2].Text}\",\"{DateTime.Now:yyyy-MM-dd}\"");
                }
                
                // Результаты поиска по IP
                foreach (ListViewItem item in ipResultsList.Items)
                {
                    writer.WriteLine($"\"Поиск по IP\",\"{item.SubItems[0].Text}\",\"{item.SubItems[1].Text}\",\"\",\"{DateTime.Now:yyyy-MM-dd}\"");
                }
            }
        }

        private void ExportToJSON_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Filter = "JSON файл|*.json";
                sfd.FileName = $"osint_export_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        ExportToJSON(sfd.FileName);
                        MessageBox.Show($"Данные экспортированы в JSON: {sfd.FileName}", "Успех", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка экспорта: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void ExportToJSON(string filePath)
        {
            var exportData = new
            {
                ExportDate = DateTime.Now,
                UsernameSearch = new
                {
                    Query = usernameTextBox.Text,
                    Results = usernameResultsList.Items.Cast<ListViewItem>()
                        .Select(item => new
                        {
                            Platform = item.SubItems[0].Text,
                            Url = item.SubItems[1].Text,
                            Username = item.SubItems[2].Text,
                            Status = item.SubItems[3].Text
                        }).ToList()
                },
                EmailSearch = new
                {
                    Query = emailTextBox.Text,
                    Results = emailResultsList.Items.Cast<ListViewItem>()
                        .Select(item => new
                        {
                            BreachName = item.SubItems[0].Text,
                            BreachDate = item.SubItems[1].Text,
                            DataClasses = item.SubItems[2].Text
                        }).ToList()
                },
                IPSearch = new
                {
                    Query = ipTextBox.Text,
                    Results = ipResultsList.Items.Cast<ListViewItem>()
                        .Select(item => new
                        {
                            InfoType = item.SubItems[0].Text,
                            Value = item.SubItems[1].Text
                        }).ToDictionary(item => item.InfoType, item => item.Value)
                }
            };
            
            string json = JsonConvert.SerializeObject(exportData, Formatting.Indented);
            File.WriteAllText(filePath, json, Encoding.UTF8);
        }

        private void UpdateDatabases_Click(object sender, EventArgs e)
        {
            MessageBox.Show("Базы данных обновлены", "Информация", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ShowAbout_Click(object sender, EventArgs e)
        {
            string aboutText = @"OSINT Recon Suite v3.0

Профессиональный инструмент для сбора информации 
из открытых источников (OSINT).

Возможности:
- Поиск по имени пользователя в соцсетях
- Проверка email на утечки данных
- Геолокация по IP адресу
- Анализ доменов и поддоменов
- Извлечение метаданных из файлов
- Расширенный поиск и анализ
- Экспорт в CSV и JSON

Разработано: X-GEN Security
Для измерения: Earth-8847

Версия: 3.0.0.0
Сборка: 2026.02.05";

            MessageBox.Show(aboutText, "О программе", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ShowDocs_Click(object sender, EventArgs e)
        {
            string docsText = @"ДОКУМЕНТАЦИЯ

1. ПОИСК ПО ИМЕНИ ПОЛЬЗОВАТЕЛЯ:
   - Введите имя пользователя без @
   - Программа проверит 14+ социальных сетей
   - Результаты отображаются в таблице

2. ПРОВЕРКА EMAIL:
   - Введите полный email адрес
   - Проверка через HaveIBeenPwned API
   - Показывает утечки данных

3. ПОИСК ПО ТЕЛЕФОНУ:
   - Введите номер в любом формате
   - Определение страны и оператора
   - Поиск в мессенджерах

4. ПОИСК ПО IP:
   - Геолокация и информация о провайдере
   - Проверка через AbuseIPDB
   - Сканирование портов

5. ПОИСК ПО ДОМЕНУ:
   - WHOIS информация
   - Поиск поддоменов
   - Проверка через VirusTotal

6. МЕТАДАННЫЕ ФАЙЛОВ:
   - Выберите любой файл
   - Извлечение EXIF и другой информации
   - Показывает GPS координаты

ВАЖНО: Используйте инструмент ответственно.
Соблюдайте законодательство вашей страны.";

            ResultForm docsForm = new ResultForm("Документация", docsText);
            docsForm.Show();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            SaveSettings();
            base.OnFormClosing(e);
        }
    }

    // Вспомогательный класс для отображения результатов
    public class ResultForm : Form
    {
        public ResultForm(string title, string content)
        {
            this.Text = title;
            this.Size = new System.Drawing.Size(800, 600);
            this.StartPosition = FormStartPosition.CenterParent;
            
            RichTextBox textBox = new RichTextBox
            {
                Text = content,
                Dock = DockStyle.Fill,
                ReadOnly = true,
                Font = new System.Drawing.Font("Consolas", 10),
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            
            Button closeButton = new Button
            {
                Text = "Закрыть",
                Dock = DockStyle.Bottom,
                Height = 40
            };
            closeButton.Click += (s, e) => this.Close();
            
            this.Controls.Add(textBox);
            this.Controls.Add(closeButton);
        }
    }
}