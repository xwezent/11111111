using System;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace OSINT_Recon_Suite
{
    public partial class SettingsForm : Form
    {
        private const string ENCRYPTION_KEY = "X-GEN-8847-OSINT-SECURE-KEY-2024";
        private readonly string configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "OSINT_Recon_Suite",
            "config.enc");

        public SettingsForm()
        {
            InitializeComponent();
            LoadSettings();
        }

        private void InitializeComponent()
        {
            this.Text = "Настройки API";
            this.Size = new System.Drawing.Size(500, 600);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            // Создание элементов управления
            TabControl tabControl = new TabControl { Dock = DockStyle.Fill };
            
            // Вкладка API Ключи
            TabPage apiPage = new TabPage("API Ключи");
            InitializeApiPage(apiPage);
            tabControl.TabPages.Add(apiPage);

            // Вкладка Настройки
            TabPage settingsPage = new TabPage("Настройки");
            InitializeSettingsPage(settingsPage);
            tabControl.TabPages.Add(settingsPage);

            // Кнопки
            Panel buttonPanel = new Panel 
            { 
                Dock = DockStyle.Bottom, 
                Height = 50 
            };
            
            Button saveButton = new Button 
            { 
                Text = "Сохранить", 
                Location = new System.Drawing.Point(320, 10),
                Size = new System.Drawing.Size(75, 30)
            };
            saveButton.Click += SaveButton_Click;
            
            Button cancelButton = new Button 
            { 
                Text = "Отмена", 
                Location = new System.Drawing.Point(400, 10),
                Size = new System.Drawing.Size(75, 30)
            };
            cancelButton.Click += (s, e) => this.Close();

            buttonPanel.Controls.Add(saveButton);
            buttonPanel.Controls.Add(cancelButton);

            this.Controls.Add(tabControl);
            this.Controls.Add(buttonPanel);
        }

        private void InitializeApiPage(TabPage page)
        {
            page.Padding = new Padding(10);

            int yPos = 20;

            // Shodan API
            AddLabelAndTextBox(page, "Shodan API Key:", ref yPos, out TextBox shodanBox);
            shodanBox.Name = "shodanApiBox";
            shodanBox.PasswordChar = '*';

            // Hunter.io API
            yPos += 40;
            AddLabelAndTextBox(page, "Hunter.io API Key:", ref yPos, out TextBox hunterBox);
            hunterBox.Name = "hunterApiBox";
            hunterBox.PasswordChar = '*';

            // VirusTotal API
            yPos += 40;
            AddLabelAndTextBox(page, "VirusTotal API Key:", ref yPos, out TextBox vtBox);
            vtBox.Name = "vtApiBox";
            vtBox.PasswordChar = '*';

            // IPinfo API
            yPos += 40;
            AddLabelAndTextBox(page, "IPinfo.io API Key:", ref yPos, out TextBox ipinfoBox);
            ipinfoBox.Name = "ipinfoApiBox";
            ipinfoBox.PasswordChar = '*';

            // Emailrep.io API
            yPos += 40;
            AddLabelAndTextBox(page, "Emailrep.io API Key:", ref yPos, out TextBox emailrepBox);
            emailrepBox.Name = "emailrepApiBox";
            emailrepBox.PasswordChar = '*';

            // Proxy настройки
            yPos += 60;
            Label proxyLabel = new Label
            {
                Text = "HTTP Прокси (host:port):",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(200, 25)
            };
            page.Controls.Add(proxyLabel);

            TextBox proxyBox = new TextBox
            {
                Location = new System.Drawing.Point(220, yPos),
                Size = new System.Drawing.Size(200, 25),
                Name = "proxyBox"
            };
            page.Controls.Add(proxyBox);

            yPos += 30;
            CheckBox useProxyCheck = new CheckBox
            {
                Text = "Использовать прокси",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(150, 25),
                Name = "useProxyCheck"
            };
            page.Controls.Add(useProxyCheck);
        }

        private void InitializeSettingsPage(TabPage page)
        {
            page.Padding = new Padding(10);

            int yPos = 20;

            // Настройки поиска
            CheckBox saveLogsCheck = new CheckBox
            {
                Text = "Сохранять логи поиска",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(200, 25),
                Name = "saveLogsCheck"
            };
            page.Controls.Add(saveLogsCheck);

            yPos += 40;
            CheckBox autoUpdateCheck = new CheckBox
            {
                Text = "Автоматически проверять обновления",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(250, 25),
                Name = "autoUpdateCheck"
            };
            page.Controls.Add(autoUpdateCheck);

            yPos += 40;
            Label timeoutLabel = new Label
            {
                Text = "Таймаут запросов (сек):",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(150, 25)
            };
            page.Controls.Add(timeoutLabel);

            NumericUpDown timeoutBox = new NumericUpDown
            {
                Location = new System.Drawing.Point(180, yPos),
                Size = new System.Drawing.Size(60, 25),
                Minimum = 5,
                Maximum = 120,
                Value = 30,
                Name = "timeoutBox"
            };
            page.Controls.Add(timeoutBox);

            yPos += 50;
            Label threadsLabel = new Label
            {
                Text = "Максимум потоков:",
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(150, 25)
            };
            page.Controls.Add(threadsLabel);

            NumericUpDown threadsBox = new NumericUpDown
            {
                Location = new System.Drawing.Point(180, yPos),
                Size = new System.Drawing.Size(60, 25),
                Minimum = 1,
                Maximum = 50,
                Value = 10,
                Name = "threadsBox"
            };
            page.Controls.Add(threadsBox);
        }

        private void AddLabelAndTextBox(TabPage page, string labelText, ref int yPos, out TextBox textBox)
        {
            Label label = new Label
            {
                Text = labelText,
                Location = new System.Drawing.Point(20, yPos),
                Size = new System.Drawing.Size(150, 25)
            };
            page.Controls.Add(label);

            textBox = new TextBox
            {
                Location = new System.Drawing.Point(180, yPos),
                Size = new System.Drawing.Size(250, 25)
            };
            page.Controls.Add(textBox);
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(configPath))
                {
                    string encrypted = File.ReadAllText(configPath);
                    string decrypted = Decrypt(encrypted);
                    var lines = decrypted.Split('\n');

                    foreach (var line in lines)
                    {
                        if (line.Contains("="))
                        {
                            var parts = line.Split('=');
                            if (parts.Length == 2)
                            {
                                SetControlValue(parts[0], parts[1]);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка загрузки настроек: {ex.Message}", 
                    "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void SetControlValue(string name, string value)
        {
            var control = FindControl(this, name);
            if (control != null)
            {
                if (control is TextBox textBox)
                    textBox.Text = value;
                else if (control is CheckBox checkBox)
                    checkBox.Checked = bool.Parse(value);
                else if (control is NumericUpDown numericBox)
                    numericBox.Value = decimal.Parse(value);
            }
        }

        private Control? FindControl(Control parent, string name)
        {
            if (parent.Name == name) return parent;
            
            foreach (Control child in parent.Controls)
            {
                var found = FindControl(child, name);
                if (found != null) return found;
            }
            return null;
        }

        private void SaveButton_Click(object sender, EventArgs e)
        {
            try
            {
                StringBuilder config = new StringBuilder();

                // Сбор значений со всех элементов управления
                CollectControlValues(this, config);

                // Шифрование и сохранение
                string encrypted = Encrypt(config.ToString());
                
                Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
                File.WriteAllText(configPath, encrypted);

                MessageBox.Show("Настройки успешно сохранены!", 
                    "Успех", MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сохранения: {ex.Message}", 
                    "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CollectControlValues(Control parent, StringBuilder sb)
        {
            foreach (Control control in parent.Controls)
            {
                if (!string.IsNullOrEmpty(control.Name))
                {
                    string value = "";
                    
                    if (control is TextBox textBox)
                        value = textBox.Text;
                    else if (control is CheckBox checkBox)
                        value = checkBox.Checked.ToString();
                    else if (control is NumericUpDown numericBox)
                        value = numericBox.Value.ToString();
                    
                    if (!string.IsNullOrEmpty(value))
                    {
                        sb.AppendLine($"{control.Name}={value}");
                    }
                }
                
                if (control.HasChildren)
                    CollectControlValues(control, sb);
            }
        }

        private string Encrypt(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(ENCRYPTION_KEY.PadRight(32).Substring(0, 32));
                aes.IV = new byte[16];
                
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] data = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(data, 0, data.Length);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private string Decrypt(string cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(ENCRYPTION_KEY.PadRight(32).Substring(0, 32));
                aes.IV = new byte[16];
                
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}