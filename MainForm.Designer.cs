namespace OSINT_Recon_Suite
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private TabControl mainTabControl;
        private MenuStrip menuStrip;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private ToolStripProgressBar progressBar;
        
        private TabPage usernameTab;
        private TextBox usernameTextBox;
        private Button usernameSearchButton;
        private ListView usernameResultsList;
        private ColumnHeader columnPlatform;
        private ColumnHeader columnURL;
        private ColumnHeader columnUsername;
        private ColumnHeader columnStatus;
        
        private TabPage emailTab;
        private TextBox emailTextBox;
        private Button emailSearchButton;
        private ListView emailResultsList;
        private ColumnHeader columnBreachName;
        private ColumnHeader columnBreachDate;
        private ColumnHeader columnDataClasses;
        
        private TabPage phoneTab;
        private TextBox phoneTextBox;
        private Button phoneSearchButton;
        private TextBox phoneResultTextBox;
        
        private TabPage ipTab;
        private TextBox ipTextBox;
        private Button ipSearchButton;
        private ListView ipResultsList;
        private ColumnHeader columnIPInfo;
        private ColumnHeader columnIPValue;
        
        private TabPage metadataTab;
        private Button metadataBrowseButton;
        private TextBox metadataFilePathBox;
        private ListView metadataResultsList;
        private ColumnHeader columnMetadataName;
        private ColumnHeader columnMetadataValue;
        
        private TabPage domainTab;
        private TextBox domainTextBox;
        private Button domainSearchButton;
        private ListView domainResultsList;
        private ColumnHeader columnDomainInfo;
        private ColumnHeader columnDomainValue;
        
        private TabPage advancedTab;
        private RichTextBox queryTextBox;
        private Button executeQueryButton;
        private ComboBox queryTypeCombo;
        
        private TabPage settingsTab;
        private TextBox shodanApiBox;
        private TextBox vtApiBox;
        private TextBox ipinfoApiBox;
        private CheckBox useProxyCheck;
        private TextBox proxyBox;
        private CheckBox saveLogsCheck;
        private CheckBox autoUpdateCheck;
        private NumericUpDown timeoutBox;
        private NumericUpDown threadsBox;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            
            this.components = new System.ComponentModel.Container();
            this.menuStrip = new MenuStrip();
            this.statusStrip = new StatusStrip();
            this.statusLabel = new ToolStripStatusLabel();
            this.progressBar = new ToolStripProgressBar();
            this.mainTabControl = new TabControl();
            this.usernameTab = new TabPage();
            this.usernameTextBox = new TextBox();
            this.usernameSearchButton = new Button();
            this.usernameResultsList = new ListView();
            this.columnPlatform = new ColumnHeader();
            this.columnURL = new ColumnHeader();
            this.columnUsername = new ColumnHeader();
            this.columnStatus = new ColumnHeader();
            this.emailTab = new TabPage();
            this.emailTextBox = new TextBox();
            this.emailSearchButton = new Button();
            this.emailResultsList = new ListView();
            this.columnBreachName = new ColumnHeader();
            this.columnBreachDate = new ColumnHeader();
            this.columnDataClasses = new ColumnHeader();
            this.phoneTab = new TabPage();
            this.phoneTextBox = new TextBox();
            this.phoneSearchButton = new Button();
            this.phoneResultTextBox = new TextBox();
            this.ipTab = new TabPage();
            this.ipTextBox = new TextBox();
            this.ipSearchButton = new Button();
            this.ipResultsList = new ListView();
            this.columnIPInfo = new ColumnHeader();
            this.columnIPValue = new ColumnHeader();
            this.domainTab = new TabPage();
            this.domainTextBox = new TextBox();
            this.domainSearchButton = new Button();
            this.domainResultsList = new ListView();
            this.columnDomainInfo = new ColumnHeader();
            this.columnDomainValue = new ColumnHeader();
            this.metadataTab = new TabPage();
            this.metadataBrowseButton = new Button();
            this.metadataFilePathBox = new TextBox();
            this.metadataResultsList = new ListView();
            this.columnMetadataName = new ColumnHeader();
            this.columnMetadataValue = new ColumnHeader();
            this.advancedTab = new TabPage();
            this.queryTypeCombo = new ComboBox();
            this.queryTextBox = new RichTextBox();
            this.executeQueryButton = new Button();
            this.settingsTab = new TabPage();
            this.shodanApiBox = new TextBox();
            this.vtApiBox = new TextBox();
            this.ipinfoApiBox = new TextBox();
            this.useProxyCheck = new CheckBox();
            this.proxyBox = new TextBox();
            this.saveLogsCheck = new CheckBox();
            this.autoUpdateCheck = new CheckBox();
            this.timeoutBox = new NumericUpDown();
            this.threadsBox = new NumericUpDown();
            
            // Главная форма
            this.Text = "OSINT Recon Suite v3.0";
            this.Size = new System.Drawing.Size(1200, 800);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            
            // Menu Strip
            InitializeMenuStrip();
            
            // Status Strip
            this.statusStrip.Items.AddRange(new ToolStripItem[] {
                this.statusLabel,
                this.progressBar
            });
            
            // Main Tab Control
            this.mainTabControl.Dock = DockStyle.Fill;
            this.mainTabControl.Margin = new Padding(5);
            
            // Username Tab
            this.usernameTab.Text = "Поиск по имени";
            this.usernameTab.Padding = new Padding(10);
            this.usernameTab.Controls.Add(this.usernameTextBox);
            this.usernameTab.Controls.Add(this.usernameSearchButton);
            this.usernameTab.Controls.Add(this.usernameResultsList);
            
            this.usernameTextBox.Location = new System.Drawing.Point(150, 20);
            this.usernameTextBox.Size = new System.Drawing.Size(300, 25);
            
            this.usernameSearchButton.Location = new System.Drawing.Point(470, 20);
            this.usernameSearchButton.Size = new System.Drawing.Size(120, 25);
            this.usernameSearchButton.Text = "Начать поиск";
            
            this.usernameResultsList.View = View.Details;
            this.usernameResultsList.Location = new System.Drawing.Point(20, 60);
            this.usernameResultsList.Size = new System.Drawing.Size(1100, 600);
            this.usernameResultsList.FullRowSelect = true;
            this.usernameResultsList.GridLines = true;
            this.usernameResultsList.Columns.AddRange(new ColumnHeader[] {
                this.columnPlatform,
                this.columnURL,
                this.columnUsername,
                this.columnStatus
            });
            this.columnPlatform.Text = "Платформа";
            this.columnPlatform.Width = 150;
            this.columnURL.Text = "URL";
            this.columnURL.Width = 400;
            this.columnUsername.Text = "Имя пользователя";
            this.columnUsername.Width = 150;
            this.columnStatus.Text = "Статус";
            this.columnStatus.Width = 100;
            
            // Email Tab
            this.emailTab.Text = "Поиск по Email";
            this.emailTab.Padding = new Padding(10);
            this.emailTab.Controls.Add(this.emailTextBox);
            this.emailTab.Controls.Add(this.emailSearchButton);
            this.emailTab.Controls.Add(this.emailResultsList);
            
            this.emailTextBox.Location = new System.Drawing.Point(130, 20);
            this.emailTextBox.Size = new System.Drawing.Size(350, 25);
            
            this.emailSearchButton.Location = new System.Drawing.Point(500, 20);
            this.emailSearchButton.Size = new System.Drawing.Size(150, 25);
            this.emailSearchButton.Text = "Проверить утечки";
            
            this.emailResultsList.View = View.Details;
            this.emailResultsList.Location = new System.Drawing.Point(20, 60);
            this.emailResultsList.Size = new System.Drawing.Size(1100, 600);
            this.emailResultsList.FullRowSelect = true;
            this.emailResultsList.Columns.AddRange(new ColumnHeader[] {
                this.columnBreachName,
                this.columnBreachDate,
                this.columnDataClasses
            });
            this.columnBreachName.Text = "Утечка";
            this.columnBreachName.Width = 200;
            this.columnBreachDate.Text = "Дата";
            this.columnBreachDate.Width = 100;
            this.columnDataClasses.Text = "Типы данных";
            this.columnDataClasses.Width = 400;
            
            // Phone Tab
            this.phoneTab.Text = "Поиск по телефону";
            this.phoneTab.Padding = new Padding(10);
            this.phoneTab.Controls.Add(this.phoneTextBox);
            this.phoneTab.Controls.Add(this.phoneSearchButton);
            this.phoneTab.Controls.Add(this.phoneResultTextBox);
            
            this.phoneTextBox.Location = new System.Drawing.Point(150, 20);
            this.phoneTextBox.Size = new System.Drawing.Size(200, 25);
            this.phoneTextBox.PlaceholderText = "+79161234567";
            
            this.phoneSearchButton.Location = new System.Drawing.Point(370, 20);
            this.phoneSearchButton.Size = new System.Drawing.Size(150, 25);
            this.phoneSearchButton.Text = "Найти информацию";
            
            this.phoneResultTextBox.Location = new System.Drawing.Point(20, 60);
            this.phoneResultTextBox.Size = new System.Drawing.Size(1100, 600);
            this.phoneResultTextBox.Multiline = true;
            this.phoneResultTextBox.ScrollBars = ScrollBars.Vertical;
            this.phoneResultTextBox.ReadOnly = true;
            
            // IP Tab
            this.ipTab.Text = "Поиск по IP";
            this.ipTab.Padding = new Padding(10);
            this.ipTab.Controls.Add(this.ipTextBox);
            this.ipTab.Controls.Add(this.ipSearchButton);
            this.ipTab.Controls.Add(this.ipResultsList);
            
            this.ipTextBox.Location = new System.Drawing.Point(110, 20);
            this.ipTextBox.Size = new System.Drawing.Size(200, 25);
            this.ipTextBox.PlaceholderText = "192.168.1.1";
            
            this.ipSearchButton.Location = new System.Drawing.Point(330, 20);
            this.ipSearchButton.Size = new System.Drawing.Size(200, 25);
            this.ipSearchButton.Text = "Геолокация и информация";
            
            this.ipResultsList.View = View.Details;
            this.ipResultsList.Location = new System.Drawing.Point(20, 60);
            this.ipResultsList.Size = new System.Drawing.Size(1100, 600);
            this.ipResultsList.FullRowSelect = true;
            this.ipResultsList.Columns.AddRange(new ColumnHeader[] {
                this.columnIPInfo,
                this.columnIPValue
            });
            this.columnIPInfo.Text = "Тип информации";
            this.columnIPInfo.Width = 200;
            this.columnIPValue.Text = "Значение";
            this.columnIPValue.Width = 400;
            
            // Domain Tab
            this.domainTab.Text = "Поиск по домену";
            this.domainTab.Padding = new Padding(10);
            this.domainTab.Controls.Add(this.domainTextBox);
            this.domainTab.Controls.Add(this.domainSearchButton);
            this.domainTab.Controls.Add(this.domainResultsList);
            
            this.domainTextBox.Location = new System.Drawing.Point(110, 20);
            this.domainTextBox.Size = new System.Drawing.Size(300, 25);
            this.domainTextBox.PlaceholderText = "example.com";
            
            this.domainSearchButton.Location = new System.Drawing.Point(430, 20);
            this.domainSearchButton.Size = new System.Drawing.Size(150, 25);
            this.domainSearchButton.Text = "Найти информацию";
            
            this.domainResultsList.View = View.Details;
            this.domainResultsList.Location = new System.Drawing.Point(20, 60);
            this.domainResultsList.Size = new System.Drawing.Size(1100, 600);
            this.domainResultsList.FullRowSelect = true;
            this.domainResultsList.Columns.AddRange(new ColumnHeader[] {
                this.columnDomainInfo,
                this.columnDomainValue
            });
            this.columnDomainInfo.Text = "Информация";
            this.columnDomainInfo.Width = 200;
            this.columnDomainValue.Text = "Значение";
            this.columnDomainValue.Width = 400;
            
            // Metadata Tab
            this.metadataTab.Text = "Метаданные файлов";
            this.metadataTab.Padding = new Padding(10);
            this.metadataTab.Controls.Add(this.metadataBrowseButton);
            this.metadataTab.Controls.Add(this.metadataFilePathBox);
            this.metadataTab.Controls.Add(this.metadataResultsList);
            
            this.metadataBrowseButton.Location = new System.Drawing.Point(20, 20);
            this.metadataBrowseButton.Size = new System.Drawing.Size(120, 25);
            this.metadataBrowseButton.Text = "Выбрать файл";
            
            this.metadataFilePathBox.Location = new System.Drawing.Point(150, 20);
            this.metadataFilePathBox.Size = new System.Drawing.Size(500, 25);
            this.metadataFilePathBox.ReadOnly = true;
            
            this.metadataResultsList.View = View.Details;
            this.metadataResultsList.Location = new System.Drawing.Point(20, 60);
            this.metadataResultsList.Size = new System.Drawing.Size(1100, 600);
            this.metadataResultsList.FullRowSelect = true;
            this.metadataResultsList.Columns.AddRange(new ColumnHeader[] {
                this.columnMetadataName,
                this.columnMetadataValue
            });
            this.columnMetadataName.Text = "Тег";
            this.columnMetadataName.Width = 200;
            this.columnMetadataValue.Text = "Значение";
            this.columnMetadataValue.Width = 500;
            
            // Advanced Tab
            this.advancedTab.Text = "Расширенный поиск";
            this.advancedTab.Padding = new Padding(10);
            this.advancedTab.Controls.Add(this.queryTypeCombo);
            this.advancedTab.Controls.Add(this.queryTextBox);
            this.advancedTab.Controls.Add(this.executeQueryButton);
            
            this.queryTypeCombo.Location = new System.Drawing.Point(130, 20);
            this.queryTypeCombo.Size = new System.Drawing.Size(200, 25);
            this.queryTypeCombo.DropDownStyle = ComboBoxStyle.DropDownList;
            this.queryTypeCombo.Items.AddRange(new string[] {
                "Кастомный HTTP запрос",
                "Поиск в базах данных",
                "Анализ сети",
                "Проверка уязвимостей"
            });
            
            this.queryTextBox.Location = new System.Drawing.Point(20, 90);
            this.queryTextBox.Size = new System.Drawing.Size(1100, 400);
            this.queryTextBox.Font = new System.Drawing.Font("Consolas", 10);
            
            this.executeQueryButton.Location = new System.Drawing.Point(20, 500);
            this.executeQueryButton.Size = new System.Drawing.Size(150, 30);
            this.executeQueryButton.Text = "Выполнить запрос";
            
            // Settings Tab
            this.settingsTab.Text = "Настройки";
            this.settingsTab.Padding = new Padding(10);
            this.settingsTab.Controls.Add(this.shodanApiBox);
            this.settingsTab.Controls.Add(this.vtApiBox);
            this.settingsTab.Controls.Add(this.ipinfoApiBox);
            this.settingsTab.Controls.Add(this.useProxyCheck);
            this.settingsTab.Controls.Add(this.proxyBox);
            this.settingsTab.Controls.Add(this.saveLogsCheck);
            this.settingsTab.Controls.Add(this.autoUpdateCheck);
            this.settingsTab.Controls.Add(this.timeoutBox);
            this.settingsTab.Controls.Add(this.threadsBox);
            
            this.shodanApiBox.Location = new System.Drawing.Point(180, 20);
            this.shodanApiBox.Size = new System.Drawing.Size(300, 25);
            this.shodanApiBox.PasswordChar = '*';
            
            this.vtApiBox.Location = new System.Drawing.Point(180, 60);
            this.vtApiBox.Size = new System.Drawing.Size(300, 25);
            this.vtApiBox.PasswordChar = '*';
            
            this.ipinfoApiBox.Location = new System.Drawing.Point(180, 100);
            this.ipinfoApiBox.Size = new System.Drawing.Size(300, 25);
            this.ipinfoApiBox.PasswordChar = '*';
            
            this.useProxyCheck.Location = new System.Drawing.Point(20, 180);
            this.useProxyCheck.Size = new System.Drawing.Size(150, 25);
            this.useProxyCheck.Text = "Использовать прокси";
            
            this.proxyBox.Location = new System.Drawing.Point(180, 180);
            this.proxyBox.Size = new System.Drawing.Size(200, 25);
            
            this.saveLogsCheck.Location = new System.Drawing.Point(20, 220);
            this.saveLogsCheck.Size = new System.Drawing.Size(200, 25);
            this.saveLogsCheck.Text = "Сохранять логи поиска";
            
            this.autoUpdateCheck.Location = new System.Drawing.Point(20, 260);
            this.autoUpdateCheck.Size = new System.Drawing.Size(250, 25);
            this.autoUpdateCheck.Text = "Автоматически проверять обновления";
            
            this.timeoutBox.Location = new System.Drawing.Point(180, 300);
            this.timeoutBox.Size = new System.Drawing.Size(60, 25);
            this.timeoutBox.Minimum = 5;
            this.timeoutBox.Maximum = 120;
            this.timeoutBox.Value = 30;
            
            this.threadsBox.Location = new System.Drawing.Point(180, 340);
            this.threadsBox.Size = new System.Drawing.Size(60, 25);
            this.threadsBox.Minimum = 1;
            this.threadsBox.Maximum = 50;
            this.threadsBox.Value = 10;
            
            // Добавление вкладок
            this.mainTabControl.TabPages.AddRange(new TabPage[] {
                this.usernameTab,
                this.emailTab,
                this.phoneTab,
                this.ipTab,
                this.domainTab,
                this.metadataTab,
                this.advancedTab,
                this.settingsTab
            });
            
            this.Controls.Add(this.mainTabControl);
            this.Controls.Add(this.menuStrip);
            this.Controls.Add(this.statusStrip);
        }

        private void InitializeMenuStrip()
        {
            // Файл
            ToolStripMenuItem fileMenu = new ToolStripMenuItem("Файл");
            
            ToolStripMenuItem newSearchItem = new ToolStripMenuItem("Новый поиск");
            newSearchItem.Click += (s, e) => ClearAllTabs();
            
            ToolStripMenuItem saveResultsItem = new ToolStripMenuItem("Сохранить результаты");
            saveResultsItem.Click += SaveResults_Click;
            
            ToolStripMenuItem exportItem = new ToolStripMenuItem("Экспорт");
            ToolStripMenuItem exportCSVItem = new ToolStripMenuItem("В CSV");
            exportCSVItem.Click += ExportToCSV_Click;
            ToolStripMenuItem exportJSONItem = new ToolStripMenuItem("В JSON");
            exportJSONItem.Click += ExportToJSON_Click;
            exportItem.DropDownItems.Add(exportCSVItem);
            exportItem.DropDownItems.Add(exportJSONItem);
            
            ToolStripMenuItem exitItem = new ToolStripMenuItem("Выход");
            exitItem.Click += (s, e) => this.Close();
            
            fileMenu.DropDownItems.Add(newSearchItem);
            fileMenu.DropDownItems.Add(new ToolStripSeparator());
            fileMenu.DropDownItems.Add(saveResultsItem);
            fileMenu.DropDownItems.Add(exportItem);
            fileMenu.DropDownItems.Add(new ToolStripSeparator());
            fileMenu.DropDownItems.Add(exitItem);
            
            // Инструменты
            ToolStripMenuItem toolsMenu = new ToolStripMenuItem("Инструменты");
            
            ToolStripMenuItem updateDBItem = new ToolStripMenuItem("Обновить базы");
            updateDBItem.Click += UpdateDatabases_Click;
            
            toolsMenu.DropDownItems.Add(updateDBItem);
            
            // Помощь
            ToolStripMenuItem helpMenu = new ToolStripMenuItem("Помощь");
            
            ToolStripMenuItem aboutItem = new ToolStripMenuItem("О программе");
            aboutItem.Click += ShowAbout_Click;
            
            ToolStripMenuItem docsItem = new ToolStripMenuItem("Документация");
            docsItem.Click += ShowDocs_Click;
            
            helpMenu.DropDownItems.Add(docsItem);
            helpMenu.DropDownItems.Add(aboutItem);
            
            this.menuStrip.Items.Add(fileMenu);
            this.menuStrip.Items.Add(toolsMenu);
            this.menuStrip.Items.Add(helpMenu);
        }
    }
}